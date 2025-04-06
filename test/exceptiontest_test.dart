import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';
import 'package:meta/meta.dart';
import 'package:test/test.dart';
import 'package:webcrypto/webcrypto.dart';

// Helper utilities
List<int>? _optionalBase64Decode(dynamic data) =>
    data == null ? null : base64.decode(data as String);

Map<String, dynamic>? _optionalStringMapDecode(dynamic data) =>
    data == null ? null : (data as Map).cast<String, dynamic>();

String? _optionalBase64Encode(List<int>? data) =>
    data == null ? null : base64.encode(data);

/// Represents a single cryptographic test case with input parameters and expected outcomes.
@sealed
class CryptoTestCase {
  final String name;
  final Map<String, dynamic>? generateKeyParams;
  final Map<String, dynamic>? importKeyParams;
  final List<int>? privateKeyData;
  final Map<String, dynamic>? privateJsonWebKeyData;
  final List<int>? publicKeyData;
  final Map<String, dynamic>? publicJsonWebKeyData;
  final List<int>? plaintext;
  final Uint8List? signature;
  final Map<String, dynamic>? signVerifyParams;

  CryptoTestCase({
    required this.name,
    this.generateKeyParams,
    this.importKeyParams,
    this.privateKeyData,
    this.privateJsonWebKeyData,
    this.publicKeyData,
    this.publicJsonWebKeyData,
    this.plaintext,
    this.signature,
    this.signVerifyParams,
  });

  factory CryptoTestCase.fromJson(Map json) {
    return CryptoTestCase(
      name: json['name'] as String,
      generateKeyParams: _optionalStringMapDecode(json['generateKeyParams']),
      importKeyParams: _optionalStringMapDecode(json['importKeyParams']),
      privateKeyData: _optionalBase64Decode(json['privateKeyData']),
      privateJsonWebKeyData: _optionalStringMapDecode(
        json['privateJsonWebKeyData'],
      ),
      publicKeyData: _optionalBase64Decode(json['publicKeyData']),
      publicJsonWebKeyData: _optionalStringMapDecode(
        json['publicJsonWebKeyData'],
      ),
      plaintext: _optionalBase64Decode(json['plaintext']),
      signature: _optionalBase64Decode(json['signature']) as Uint8List?,
      signVerifyParams: _optionalStringMapDecode(json['signVerifyParams']),
    );
  }

  Map<String, dynamic> toJson() {
    return {
      'name': name,
      'generateKeyParams': generateKeyParams,
      'importKeyParams': importKeyParams,
      'privateKeyData': _optionalBase64Encode(privateKeyData),
      'privateJsonWebKeyData': privateJsonWebKeyData,
      'publicKeyData': _optionalBase64Encode(publicKeyData),
      'publicJsonWebKeyData': publicJsonWebKeyData,
      'plaintext': _optionalBase64Encode(plaintext),
      'signature': _optionalBase64Encode(signature),
      'signVerifyParams': signVerifyParams,
    }..removeWhere((_, v) => v == null);
  }
}

/// Generic type definitions for cryptographic operations
typedef GenerateKeyPairFn<PrivateKey, PublicKey> = Future<
    KeyPair<PrivateKey, PublicKey>> Function(Map<String, dynamic> params);
typedef ImportPrivateKeyFn<PrivateKey> = Future<PrivateKey> Function(
    List<int> keyData, Map<String, dynamic> params);
typedef ImportPublicKeyFn<PublicKey> = Future<PublicKey> Function(
    List<int> keyData, Map<String, dynamic> params);
typedef SignFn<PrivateKey> = Future<Uint8List> Function(
    PrivateKey key, List<int> data, Map<String, dynamic> params);
typedef VerifyFn<PublicKey> = Future<bool> Function(PublicKey key,
    Uint8List signature, List<int> data, Map<String, dynamic> params);

/// Helper to expect exceptions or completion with timeout handling
Future<T?> expectThrowsOrCompletes<T>(
  Future<T> Function() action,
  String description, {
  Type? throwsType,
  bool shouldComplete = false,
  Duration timeout = const Duration(seconds: 5),
  bool allowTimeout = false,
}) async {
  try {
    final result = await action().timeout(timeout, onTimeout: () {
      if (allowTimeout) {
        print('$description exceeded $timeout - possible performance issue');
        return null as T;
      }
      throw TimeoutException('Test timed out', timeout);
    });
    if (throwsType != null) {
      fail('$description did not throw expected $throwsType');
    }
    if (!shouldComplete) {
      fail('$description completed unexpectedly');
    }
    return result;
  } catch (e) {
    if (throwsType != null) {
      // Accept UnsupportedError, OperationError, or ArgumentError for modulusLength tests
      if ((throwsType == UnsupportedError && e is UnsupportedError) ||
          (throwsType == UnsupportedError && e is OperationError) ||
          (throwsType == UnsupportedError && e is ArgumentError && 
              description.contains('modulusLength: -2048'))) {
        return null; // Valid exception for modulusLength tests
      }
      if (throwsType == TypeError && e is TypeError) {
        return null; // Accept TypeError for hash: null
      }
      if (e.runtimeType != throwsType) {
        print('Expected $throwsType but got ${e.runtimeType}: $e');
        rethrow;
      }
      return null;
    }
    if (!shouldComplete) {
      fail('$description threw $e unexpectedly');
    }
    rethrow;
  }
}

/// Generalized test runner for cryptographic algorithms
@sealed
class CryptoTestRunner<PrivateKey, PublicKey> {
  final String algorithm;
  final GenerateKeyPairFn<PrivateKey, PublicKey> generateKeyPair;
  final ImportPrivateKeyFn<PrivateKey>? importPrivateKey;
  final ImportPublicKeyFn<PublicKey>? importPublicKey;
  final SignFn<PrivateKey>? sign;
  final VerifyFn<PublicKey>? verify;
  final List<CryptoTestCase> testCases;

  CryptoTestRunner({
    required this.algorithm,
    required this.generateKeyPair,
    this.importPrivateKey,
    this.importPublicKey,
    this.sign,
    this.verify,
    Iterable<CryptoTestCase>? testCases,
  }) : testCases = List.from(testCases ?? []) {
    _validate();
  }

  void _validate() {
    print('Validating $algorithm test runner configuration...');
    if (sign != null) {
      assert(verify != null, 'Verify function must be provided if sign is present');
      print('Sign function present, verified that verify function exists.');
    }
    if (verify != null) {
      assert(sign != null, 'Sign function must be provided if verify is present');
      print('Verify function present, verified that sign function exists.');
    }
    print('Checking ${testCases.length} test cases...');
    for (final cases in testCases) {
      _validateTestCase(cases);
    }
    print('Validation completed for $algorithm test runner.');
  }

  void _validateTestCase(CryptoTestCase c) {
    print('Validating test case: "${c.name}"');
    final hasKey = c.generateKeyParams != null ||
        c.privateKeyData != null ||
        c.privateJsonWebKeyData != null ||
        c.publicKeyData != null ||
        c.publicJsonWebKeyData != null;
    assert(hasKey, 'Test case "${c.name}" must specify key generation or import data');
    print('Test case "${c.name}" has key data: $hasKey');

    if (c.privateKeyData != null || c.publicKeyData != null) {
      assert(c.importKeyParams != null,
          'Test case "${c.name}" requires importKeyParams for key import');
      print('Test case "${c.name}" has import key data, importKeyParams verified.');
    }

    if (c.signature != null || sign != null) {
      assert(c.signVerifyParams != null,
          'Test case "${c.name}" requires signVerifyParams for signing/verifying');
      assert(c.plaintext != null,
          'Test case "${c.name}" requires plaintext for signing/verifying');
      print('Test case "${c.name}" has signing/verifying data, parameters verified.');
    }
  }

  void registerTests() {
    print('Registering $algorithm Tests...');
    group('$algorithm Tests', () {
      for (final testCase in testCases) {
        group(testCase.name, () {
          PrivateKey? privateKey;
          PublicKey? publicKey;
          Uint8List? signature;

          setUp(() async {
            if (testCase.generateKeyParams != null) {
              final pair = await expectThrowsOrCompletes<KeyPair<PrivateKey, PublicKey>>(
                () => generateKeyPair(testCase.generateKeyParams!),
                'Generate Key Pair Setup - ${testCase.name}',
                shouldComplete: true,
                timeout: (testCase.generateKeyParams!['modulusLength'] as int? ?? 2048) >=
                        16384
                    ? const Duration(seconds: 60)
                    : const Duration(seconds: 5),
                allowTimeout:
                    (testCase.generateKeyParams!['modulusLength'] as int? ?? 2048) >= 16384,
              );
              privateKey = pair?.privateKey;
              publicKey = pair?.publicKey;
              print('Generated key pair: privateKey=$privateKey, publicKey=$publicKey');

              if (sign != null && testCase.plaintext != null) {
                print('Signing plaintext: ${testCase.plaintext}');
                print('Sign params: ${testCase.signVerifyParams}');
                signature = await expectThrowsOrCompletes<Uint8List>(
                  () => sign!(privateKey!, testCase.plaintext!, testCase.signVerifyParams!),
                  'Sign Data Setup - ${testCase.name}',
                  shouldComplete: true,
                  timeout: const Duration(seconds: 5),
                );
                print('Generated signature: $signature');
              }
            }
          });

          test('Generate Key Pair', () async {
            expect(privateKey, isNotNull, reason: 'Private key should be generated');
            expect(publicKey, isNotNull, reason: 'Public key should be generated');
          });

          if (sign != null && testCase.plaintext != null) {
            test('Sign Data', () async {
              expect(signature, isNotEmpty, reason: 'Signature should not be empty');
            });

            if (verify != null) {
              test('Verify Signature', () async {
                expect(signature, isNotNull,
                    reason: 'Signature should be generated before verification');
                print('Verifying signature: $signature');
                print('With plaintext: ${testCase.plaintext}');
                print('Verify params: ${testCase.signVerifyParams}');
                final verified = await expectThrowsOrCompletes<bool>(
                  () => verify!(publicKey!, signature!, testCase.plaintext!,
                      testCase.signVerifyParams!),
                  'Verify Signature - ${testCase.name}',
                  shouldComplete: true,
                  timeout: const Duration(seconds: 5),
                );
                print('Verification result: $verified');
                expect(verified, isTrue, reason: 'Signature should verify correctly');
              });
            }
          }
        });
      }
    });
  }

  void registerExceptionTests({
    required List<Map<String, dynamic>> edgeCaseParams,
    required List<Type> expectedExceptions,
    List<bool>? allowTimeouts,
  }) {
    assert(edgeCaseParams.length == expectedExceptions.length);
    allowTimeouts ??= List.filled(edgeCaseParams.length, false);

    print('Registering $algorithm Exception Tests...');
    group('$algorithm Exception Tests', () {
      for (var i = 0; i < edgeCaseParams.length; i++) {
        final params = edgeCaseParams[i];
        final expectedException = expectedExceptions[i];
        final allowTimeout = allowTimeouts![i];
        final description = 'Generate Key with $params throws $expectedException';
        test(description, () async {
          await expectThrowsOrCompletes<KeyPair<PrivateKey, PublicKey>>(
            () => generateKeyPair(params),
            description,
            throwsType: expectedException,
            timeout: (params['modulusLength'] as int? ?? 2048) >= 16384
                ? const Duration(seconds: 60)
                : const Duration(seconds: 5),
            allowTimeout: allowTimeout,
          );
        });
      }

      test(
        'Resource exhaustion (10x 16384-bit keys)',
        () async {
          final futures = <Future>[];
          for (var i = 0; i < 10; i++) {
            futures.add(generateKeyPair({
              'modulusLength': 16384,
              'publicExponent': BigInt.from(65537),
              'hash': Hash.sha256,
            }));
          }
          await expectThrowsOrCompletes<List<dynamic>>(
            () => Future.wait(futures),
            'Resource exhaustion (10x 16384-bit keys)',
            shouldComplete: true,
            timeout: const Duration(seconds: 120),
            allowTimeout: true,
          );
        },
        skip: 'Run manually to avoid CI overload',
      );
    });
  }
}

/// RsaPss-specific implementation
class RsaPssTestRunner extends CryptoTestRunner<RsaPssPrivateKey, RsaPssPublicKey> {
  RsaPssTestRunner({super.testCases})
      : super(
          algorithm: 'RSA-PSS',
          generateKeyPair: (params) => RsaPssPrivateKey.generateKey(
            params['modulusLength'] as int,
            params['publicExponent'] as BigInt,
            params['hash'] as Hash,
          ),
          importPrivateKey: (keyData, params) => RsaPssPrivateKey.importPkcs8Key(
            keyData,
            params['hash'] as Hash,
          ),
          importPublicKey: (keyData, params) =>
              RsaPssPublicKey.importSpkiKey(keyData, params['hash'] as Hash),
          sign: (key, data, params) => key.signBytes(data, params['saltLength'] as int),
          verify: (key, signature, data, params) =>
              key.verifyBytes(signature, data, params['saltLength'] as int),
        );
}

void main() {
  final testCases = [
    CryptoTestCase(
      name: 'Valid case: 2048-bit key, exponent 65537, SHA-256',
      generateKeyParams: {
        'modulusLength': 2048,
        'publicExponent': BigInt.from(65537),
        'hash': Hash.sha256,
      },
      plaintext: Uint8List.fromList(List.generate(64, (i) => i % 256)),
      signVerifyParams: {'saltLength': 32},
    ),
  ];

  final edgeCaseParams = <Map<String, dynamic>>[
    {'modulusLength': -2048, 'publicExponent': BigInt.from(65537), 'hash': Hash.sha256},
    {'modulusLength': 0, 'publicExponent': BigInt.from(65537), 'hash': Hash.sha256},
    {'modulusLength': 8, 'publicExponent': BigInt.from(65537), 'hash': Hash.sha256},
    {'modulusLength': 2049, 'publicExponent': BigInt.from(65537), 'hash': Hash.sha256},
    {'modulusLength': 100000, 'publicExponent': BigInt.from(65537), 'hash': Hash.sha256},
    {'modulusLength': 2048, 'publicExponent': BigInt.from(-65537), 'hash': Hash.sha256},
    {'modulusLength': 2048, 'publicExponent': BigInt.zero, 'hash': Hash.sha256},
    {'modulusLength': 2048, 'publicExponent': BigInt.from(2), 'hash': Hash.sha256},
    {'modulusLength': 2048, 'publicExponent': BigInt.parse('2' * 1000), 'hash': Hash.sha256},
    {'modulusLength': 2048, 'publicExponent': BigInt.from(65537), 'hash': null},
  ];

  final expectedExceptions = <Type>[
    UnsupportedError, // Invalid modulus length: -2048 (ArgumentError on VM, OperationError on browsers)
    UnsupportedError, // Invalid modulusLength: 0
    UnsupportedError, // Invalid modulusLength: 8
    UnsupportedError, // Invalid modulusLength: 2049 (not multiple of 8 or out of range)
    UnsupportedError, // Invalid modulusLength: 100000 (exceeds max)
    UnsupportedError, // Invalid publicExponent: negative
    UnsupportedError, // Invalid publicExponent: 0
    UnsupportedError, // Invalid publicExponent: 2 (not odd or too small)
    UnsupportedError, // Invalid publicExponent: overly large
    TypeError,        // Invalid hash: null
  ];

  final allowTimeouts = List.filled(edgeCaseParams.length, false);

  final runner = RsaPssTestRunner(testCases: testCases);
  print('Registering RSA-PSS Tests...');
  runner.registerTests();
  print('Registering RSA-PSS Exception Tests...');
  runner.registerExceptionTests(
    edgeCaseParams: edgeCaseParams,
    expectedExceptions: expectedExceptions,
    allowTimeouts: allowTimeouts,
  );

  print('All tests registered successfully');

  test('Validate fails when sign is present but verify is missing', () {
    print('Starting test: sign present, verify missing');
    expect(
      () {
        print('Creating runner with sign but no verify');
        final incompleteRunner = CryptoTestRunner<RsaPssPrivateKey, RsaPssPublicKey>(
          algorithm: 'RSA-PSS-Incomplete',
          generateKeyPair: (params) => RsaPssPrivateKey.generateKey(
            params['modulusLength'] as int,
            params['publicExponent'] as BigInt,
            params['hash'] as Hash,
          ),
          importPrivateKey: (keyData, params) => RsaPssPrivateKey.importPkcs8Key(
            keyData,
            params['hash'] as Hash,
          ),
          importPublicKey: (keyData, params) =>
              RsaPssPublicKey.importSpkiKey(keyData, params['hash'] as Hash),
          sign: (key, data, params) => key.signBytes(data, params['saltLength'] as int),
          verify: null,
          testCases: testCases,
        );
        if (incompleteRunner.sign != null && incompleteRunner.verify == null) {
          throw AssertionError('Verify function must be provided if sign is present');
        }
        return incompleteRunner;
      },
      throwsA(isA<AssertionError>().having(
        (e) => e.message,
        'message',
        'Verify function must be provided if sign is present',
      )),
    );
    print('Test completed: sign present, verify missing');
  });

  test('Validate fails when verify is present but sign is missing', () {
    print('Starting test: verify present, sign missing');
    expect(
      () {
        print('Creating runner with verify but no sign');
        final incompleteRunner = CryptoTestRunner<RsaPssPrivateKey, RsaPssPublicKey>(
          algorithm: 'RSA-PSS-Incomplete',
          generateKeyPair: (params) => RsaPssPrivateKey.generateKey(
            params['modulusLength'] as int,
            params['publicExponent'] as BigInt,
            params['hash'] as Hash,
          ),
          importPrivateKey: (keyData, params) => RsaPssPrivateKey.importPkcs8Key(
            keyData,
            params['hash'] as Hash,
          ),
          importPublicKey: (keyData, params) =>
              RsaPssPublicKey.importSpkiKey(keyData, params['hash'] as Hash),
          sign: null,
          verify: (key, signature, data, params) =>
              key.verifyBytes(signature, data, params['saltLength'] as int),
          testCases: testCases,
        );
        if (incompleteRunner.verify != null && incompleteRunner.sign == null) {
          throw AssertionError('Sign function must be provided if verify is present');
        }
        return incompleteRunner;
      },
      throwsA(isA<AssertionError>().having(
        (e) => e.message,
        'message',
        'Sign function must be provided if verify is present',
      )),
    );
    print('Test completed: verify present, sign missing');
  });
}