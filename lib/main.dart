import 'dart:async';
import 'dart:io';
import 'dart:typed_data';
import 'package:cryptography_flutter/cryptography_flutter.dart';
import 'package:flutter/material.dart';
import 'package:cryptography/cryptography.dart';
import 'package:flutter/services.dart';
import 'dart:math';
import 'dart:convert';
import 'package:http/http.dart' as http;
import 'package:google_fonts/google_fonts.dart';
import 'package:flutter/cupertino.dart';
import 'package:flutter_sharing_intent/flutter_sharing_intent.dart';
import 'package:flutter_sharing_intent/model/sharing_file.dart';

final secureRandom = Random.secure();
const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

void main() {
  runApp(const PasshareMain());
}

class PasshareMain extends StatelessWidget {
  const PasshareMain({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      darkTheme: ThemeData.dark().copyWith(
        colorScheme: ColorScheme.fromSeed(
          seedColor: Colors.blue,
          brightness: Brightness.dark,
        ),
        useMaterial3: true,
      ),
      theme: ThemeData.from(
        colorScheme: ColorScheme.fromSeed(seedColor: Colors.blue),
        useMaterial3: true,
      ),
      home: const LandingPage(),
    );
  }
}

class LandingPage extends StatefulWidget {
  const LandingPage({super.key});
  @override
  State<LandingPage> createState() => _LandingPageState();
}

class _LandingPageState extends State<LandingPage> {
  final TextEditingController _passwordInput = TextEditingController();
  final TextEditingController _passphraseInput = TextEditingController();
  final TextEditingController _idInput =
      TextEditingController(text: 0.toString());
  bool _decryptionError = false;
  Map? _lastResponse;
  String? _encPassphrase;
  ByteBuffer? _pbkdf2Salt;

  late StreamSubscription _intentDataStreamSubscription;

  @override
  void initState() {
    super.initState();
    // For shared passwords coming from outside the app while the app is in the memory
    _intentDataStreamSubscription = FlutterSharingIntent.instance
        .getMediaStream()
        .listen((List<SharedFile> value) {
      if (value.isNotEmpty && value[0].type == SharedMediaType.TEXT) {
        _passwordInput.text = value[0].value!;
        _uploadPassword();
      }
    });

    // For shjared passwords coming from outside the app while the app is closed
    FlutterSharingIntent.instance
        .getInitialSharing()
        .then((List<SharedFile> value) {
      if (value.isNotEmpty && value[0].type == SharedMediaType.TEXT) {
        _passwordInput.text = value[0].value!;
        _uploadPassword();
      }
    });
  }

  String getRandomString([int length = 8]) {
    var res = '';
    for (var i = 0; i < length; i++) {
      res += chars[secureRandom.nextInt(chars.length)];
    }
    return res;
  }

  ByteBuffer getRandomBytes([int length = 6]) {
    var res = ByteData(length);
    for (var i = 0; i < length; i++) {
      res.setUint8(i, secureRandom.nextInt(256));
    }
    return res.buffer;
  }

  void _showDialog(Widget content, List actions) {
    if (Platform.isIOS) {
      showCupertinoDialog(
        context: context,
        builder: (ctx) => CupertinoAlertDialog(
          content: content,
          actions: [
            for (final action in actions)
              CupertinoDialogAction(
                onPressed: () {
                  action['onPressed'](ctx);
                },
                child: Text(action['text']),
              )
          ],
        ),
      );
    } else {
      showDialog(
        context: context,
        builder: (ctx) => AlertDialog(
          content: content,
          actions: [
            for (final action in actions)
              ElevatedButton(
                onPressed: () {
                  action['onPressed'](ctx);
                },
                child: Text(action['text']),
              )
          ],
        ),
      );
    }
  }

  void _uploadPassword() async {
    final pbkdf2 = FlutterPbkdf2(
      macAlgorithm: Hmac.sha256(),
      bits: 256,
      iterations: 100000,
      fallback: Pbkdf2.hmacSha256(iterations: 100000, bits: 256),
    );

    _encPassphrase = getRandomString();
    _pbkdf2Salt = getRandomBytes(16);

    // Calculate a hash that can be stored in the database
    final encKey = await pbkdf2.deriveKeyFromPassword(
      // Password given by the user.
      password: _encPassphrase!,
      nonce: _pbkdf2Salt!.asUint8List(),
    );

    final algorithm = FlutterAesGcm.with256bits();

    // Encrypt
    final secretBox = await algorithm.encrypt(_passwordInput.text.codeUnits,
        secretKey: encKey, nonce: getRandomBytes(16).asUint8List());

    final ciphertext = secretBox.cipherText + secretBox.mac.bytes;

    final response =
        await http.post(Uri.parse('https://anpass.de/api/save_pass'),
            headers: <String, String>{
              'Content-Type': 'application/json; charset=UTF-8',
            },
            body: jsonEncode({
              'ciphertext': base64Encode(ciphertext),
              'iv': base64Encode(secretBox.nonce),
              'salt': base64Encode(_pbkdf2Salt!.asUint8List())
            }));

    final resParsed =
        response.body.isNotEmpty ? jsonDecode(response.body) : null;

    if (!context.mounted) {
      return;
    }

    if (resParsed != null) {
      _showDialog(
        Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            const Text(
              "Success",
              style: TextStyle(fontSize: 20, fontWeight: FontWeight.bold),
            ),
            const SizedBox(height: 20),
            Row(
              children: [
                const Text(
                  "ID : ",
                  style: TextStyle(fontWeight: FontWeight.bold),
                ),
                Container(
                  padding: const EdgeInsets.all(5),
                  child: SelectableText(
                    style: GoogleFonts.sourceCodePro(
                      fontSize: 18,
                    ),
                    resParsed['id'].toString(),
                  ),
                ),
              ],
            ),
            Row(
              children: [
                const SelectableText("Passphrase : ",
                    style: TextStyle(fontWeight: FontWeight.bold)),
                SelectableText(
                  style: GoogleFonts.sourceCodePro(
                    fontSize: 18,
                  ),
                  _encPassphrase!,
                )
              ],
            ),
            const SizedBox(height: 10),
            const Text(
              "The password will be automatically deleted from the server after 90 seconds !",
              style: TextStyle(color: Colors.grey),
            )
          ],
        ),
        [
          {
            'onPressed': (ctx) {
              Navigator.pop(ctx);
            },
            'text': 'Okay',
          }
        ],
      );
    } else {
      _showDialog(
        const Column(mainAxisSize: MainAxisSize.min, children: [
          Text(
            "Error",
            style: TextStyle(fontSize: 20, fontWeight: FontWeight.bold),
          ),
          SizedBox(height: 20),
          Text("An error occured while uploading the password"),
        ]),
        [
          {
            'onPressed': (ctx) {
              Navigator.pop(ctx);
            },
            'text': 'Okay'
          }
        ],
      );
    }
  }

  void _getPassword() async {
    String? decryptedText;

    if (_lastResponse == null && !_decryptionError) {
      try {
        final response =
            await http.post(Uri.parse('https://anpass.de/api/get_pass'),
                headers: <String, String>{
                  'Content-Type': 'application/json; charset=UTF-8',
                },
                body: jsonEncode({
                  'id': int.parse(_idInput.text),
                }));

        final resParsed =
            response.body.isNotEmpty ? jsonDecode(response.body) : null;

        _lastResponse = resParsed;
      } catch (e) {}
    }

    if (_lastResponse != null) {
      try {
        final pbkdf2 = FlutterPbkdf2(
          macAlgorithm: Hmac.sha256(),
          bits: 256,
          iterations: 100000,
          fallback: Pbkdf2.hmacSha256(iterations: 100000, bits: 256),
        );

        // Calculate a hash that can be stored in the database
        final encKey = await pbkdf2.deriveKeyFromPassword(
          // Password given by the user.
          password: _passphraseInput.text,
          nonce: base64Decode(_lastResponse!['salt']),
        );

        final ciphertextByes = base64Decode(_lastResponse!['ciphertext']);
        final ciphertext = ciphertextByes.sublist(0,
            ciphertextByes.length - 16); // Remove the mac from the ciphertext
        final mac = ciphertextByes.sublist(ciphertextByes.length - 16);

        final algorithm = FlutterAesGcm.with256bits();
        final decrypted = await algorithm.decrypt(
          SecretBox(
            ciphertext,
            nonce: base64Decode(_lastResponse!['iv']),
            mac: Mac(mac),
          ),
          secretKey: encKey,
        );

        decryptedText = String.fromCharCodes(decrypted);
        _lastResponse = null;
        _decryptionError = false;
      } catch (e) {
        _decryptionError = true;
      }
    }

    if (!context.mounted) {
      return;
    }

    if (decryptedText != null && decryptedText.isNotEmpty) {
      _showDialog(
        Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            const Text(
              "Success",
              style: TextStyle(fontSize: 20, fontWeight: FontWeight.bold),
            ),
            const SizedBox(height: 20),
            Row(
              children: [
                const Text(
                  "Password : ",
                  style: TextStyle(fontWeight: FontWeight.bold),
                ),
                Expanded(
                  child: Container(
                    padding: const EdgeInsets.all(5),
                    child: SelectableText(
                      style: GoogleFonts.sourceCodePro(
                        fontSize: 18,
                      ),
                      decryptedText,
                    ),
                  ),
                ),
              ],
            ),
          ],
        ),
        [
          {
            'onPressed': (ctx) {
              Clipboard.setData(ClipboardData(text: decryptedText!));
              Navigator.pop(ctx);
            },
            'text': 'Copy'
          }
        ],
      );
    } else {
      _showDialog(
        const Column(mainAxisSize: MainAxisSize.min, children: [
          Text(
            "Error",
            style: TextStyle(fontSize: 20, fontWeight: FontWeight.bold),
          ),
          SizedBox(height: 20),
          Text("An error occured while uploading the password"),
        ]),
        [
          {
            'onPressed': (ctx) {
              Navigator.pop(ctx);
            },
            'text': 'Okay'
          }
        ],
      );
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        // backgroundColor: Theme.of(context).colorScheme.inversePrimary,
        title: const Text("🔒 Passhare"),
      ),
      body: SingleChildScrollView(
        child: Column(
          children: <Widget>[
            Card(
              margin: const EdgeInsets.all(10),
              child: Container(
                padding: const EdgeInsets.all(10),
                child: Column(
                  children: <Widget>[
                    const Text("Send", style: TextStyle(fontSize: 20)),
                    const Text(
                        "Please enter the password you want to share in the input field below"),
                    const SizedBox(height: 10),
                    TextField(
                      controller: _passwordInput,
                      decoration: const InputDecoration(
                        border: OutlineInputBorder(),
                        labelText: 'Password',
                      ),
                      obscureText: true,
                      enableSuggestions: false,
                      autocorrect: false,
                    ),
                    const SizedBox(height: 10),
                    const Text(
                        "You're password will be encrypted using AES-256-GCM before it's sent to the server.",
                        style: TextStyle(fontWeight: FontWeight.bold)),
                    const SizedBox(height: 10),
                    ElevatedButton(
                      onPressed: _uploadPassword,
                      child: const Text("Send"),
                    ),
                  ],
                ),
              ),
            ),
            Card(
              margin: const EdgeInsets.all(10),
              child: Container(
                padding: const EdgeInsets.all(10),
                child: Column(
                  children: <Widget>[
                    const Text("Get", style: TextStyle(fontSize: 20)),
                    const Text(
                        "Please enter the id and the passphrase to retrieve your password"),
                    const SizedBox(height: 10),
                    TextField(
                      controller: _idInput,
                      keyboardType: TextInputType.number,
                      decoration: const InputDecoration(
                        border: OutlineInputBorder(),
                        labelText: 'Id',
                      ),
                      enableSuggestions: false,
                      autocorrect: false,
                    ),
                    const SizedBox(height: 10),
                    TextField(
                      controller: _passphraseInput,
                      decoration: const InputDecoration(
                        border: OutlineInputBorder(),
                        labelText: 'Passphrase',
                      ),
                      enableSuggestions: false,
                      autocorrect: false,
                    ),
                    const SizedBox(height: 10),
                    const Text(
                        "After it's retrieved the password will be deleted from the server.",
                        style: TextStyle(fontWeight: FontWeight.bold)),
                    const SizedBox(height: 10),
                    ElevatedButton(
                      onPressed: _getPassword,
                      child: const Text("Get"),
                    ),
                  ],
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }

  @override
  void dispose() {
    _intentDataStreamSubscription.cancel();
    super.dispose();
  }
}
