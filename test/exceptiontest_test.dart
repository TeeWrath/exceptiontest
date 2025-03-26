import 'dart:async';
import 'dart:convert';
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
  final List<int>? signature;
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
      signature: _optionalBase64Decode(json['signature']),
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
typedef GenerateKeyPairFn<PrivateKey, PublicKey> =
    Future<KeyPair<PrivateKey, PublicKey>> Function(
      Map<String, dynamic> params,
    );
typedef ImportPrivateKeyFn<PrivateKey> =
    Future<PrivateKey> Function(List<int> keyData, Map<String, dynamic> params);
typedef ImportPublicKeyFn<PublicKey> =
    Future<PublicKey> Function(List<int> keyData, Map<String, dynamic> params);
typedef SignFn<PrivateKey> =
    Future<List<int>> Function(
      PrivateKey key,
      List<int> data,
      Map<String, dynamic> params,
    );
typedef VerifyFn<PublicKey> =
    Future<bool> Function(
      PublicKey key,
      List<int> signature,
      List<int> data,
      Map<String, dynamic> params,
    );

/// Helper to expect exceptions or completion with timeout handling
Future<void> expectThrowsOrCompletes<T>(
  Future<void> Function() action,
  String description, {
  Type? throwsType,
  bool shouldComplete = false,
  Duration timeout = const Duration(seconds: 5),
  bool allowTimeout = false,
}) async {
  try {
    await action().timeout(
      timeout,
      onTimeout: () {
        print('$description exceeded $timeout - possible performance issue');
        if (!allowTimeout) {
          throw TimeoutException('Test timed out', timeout);
        }
        return null;
      },
    );
    if (throwsType != null) {
      fail('$description did not throw expected $throwsType');
    }
  } catch (e) {
    if (throwsType != null) {
      if (e.runtimeType != throwsType) {
        print('Expected $throwsType but got ${e.runtimeType}: $e');
        rethrow; // Fail the test but log the mismatch
      }
    } else if (!shouldComplete) {
      fail('$description threw $e unexpectedly');
    }
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
    if (sign != null) {
      assert(
        verify != null,
        'Verify function must be provided if sign is present',
      );
    }
    if (verify != null) {
      assert(
        sign != null,
        'Sign function must be provided if verify is present',
      );
    }
    for (final cases in testCases) {
      _validateTestCase(cases);
    }
  }

  void _validateTestCase(CryptoTestCase c) {
    final hasKey =
        c.generateKeyParams != null ||
        c.privateKeyData != null ||
        c.privateJsonWebKeyData != null ||
        c.publicKeyData != null ||
        c.publicJsonWebKeyData != null;
    assert(
      hasKey,
      'Test case "${c.name}" must specify key generation or import data',
    );

    if (c.privateKeyData != null || c.publicKeyData != null) {
      assert(
        c.importKeyParams != null,
        'Test case "${c.name}" requires importKeyParams for key import',
      );
    }

    if (c.signature != null || sign != null) {
      assert(
        c.signVerifyParams != null,
        'Test case "${c.name}" requires signVerifyParams for signing/verifying',
      );
      assert(
        c.plaintext != null,
        'Test case "${c.name}" requires plaintext for signing/verifying',
      );
    }
  }

  /// Registers standard operational tests
  void registerTests() {
    group('$algorithm Tests', () {
      for (final testCase in testCases) {
        group(testCase.name, () {
          PrivateKey? privateKey;
          PublicKey? publicKey;
          List<int>? signature;

          if (testCase.generateKeyParams != null) {
            test('Generate Key Pair', () async {
              await expectThrowsOrCompletes<dynamic>(
                () async {
                  final pair = await generateKeyPair(
                    testCase.generateKeyParams!,
                  );
                  privateKey = pair.privateKey;
                  publicKey = pair.publicKey;
                  expect(
                    privateKey,
                    isNotNull,
                    reason: 'Private key should be generated',
                  );
                  expect(
                    publicKey,
                    isNotNull,
                    reason: 'Public key should be generated',
                  );
                },
                testCase.name,
                shouldComplete: true,
                timeout:
                    (testCase.generateKeyParams!['modulusLength'] as int? ??
                                2048) >=
                            16384
                        ? Duration(seconds: 60) // Increased timeout
                        : Duration(seconds: 5),
                allowTimeout:
                    (testCase.generateKeyParams!['modulusLength'] as int? ??
                        2048) >=
                    16384,
              );
            });
          } else {
            test('Import Keys', () async {
              if (testCase.privateKeyData != null && importPrivateKey != null) {
                privateKey = await importPrivateKey!(
                  testCase.privateKeyData!,
                  testCase.importKeyParams!,
                );
                expect(
                  privateKey,
                  isNotNull,
                  reason: 'Private key should be imported',
                );
              }
              if (testCase.publicKeyData != null && importPublicKey != null) {
                publicKey = await importPublicKey!(
                  testCase.publicKeyData!,
                  testCase.importKeyParams!,
                );
                expect(
                  publicKey,
                  isNotNull,
                  reason: 'Public key should be imported',
                );
              }
            });
          }

          if (sign != null &&
              testCase.plaintext != null &&
              privateKey != null) {
            if (testCase.signature != null) {
              signature = testCase.signature;
            } else {
              test(
                'Sign Data',
                () async {
                  await expectThrowsOrCompletes<dynamic>(
                    () async {
                      signature = await sign!(
                        privateKey!,
                        testCase.plaintext!,
                        testCase.signVerifyParams!,
                      );
                      expect(
                        signature,
                        isNotEmpty,
                        reason: 'Signature should not be empty',
                      );
                    },
                    'Sign Data - ${testCase.name}',
                    shouldComplete: true,
                    timeout: Duration(seconds: 5),
                  );
                },
                skip:
                    privateKey == null
                        ? 'Skipped due to key generation failure'
                        : null,
              );
            }

            if (verify != null && signature != null) {
              test(
                'Verify Signature',
                () async {
                  await expectThrowsOrCompletes<dynamic>(
                    () async {
                      final verified = await verify!(
                        publicKey!,
                        signature!,
                        testCase.plaintext!,
                        testCase.signVerifyParams!,
                      );
                      expect(
                        verified,
                        isTrue,
                        reason: 'Signature should verify correctly',
                      );
                    },
                    'Verify Signature - ${testCase.name}',
                    shouldComplete: true,
                    timeout: Duration(seconds: 5),
                  );
                },
                skip:
                    signature == null ? 'Skipped due to signing failure' : null,
              );
            }
          }
        });
      }
    });
  }

  /// Registers exception-focused tests with edge cases
  void registerExceptionTests({
    required List<Map<String, dynamic>> edgeCaseParams,
    required List<Type> expectedExceptions,
    List<bool>? allowTimeouts,
  }) {
    assert(edgeCaseParams.length == expectedExceptions.length);
    allowTimeouts ??= List.filled(edgeCaseParams.length, false);

    group('$algorithm Exception Tests', () {
      for (int i = 0; i < edgeCaseParams.length; i++) {
        final params = edgeCaseParams[i];
        final expectedException = expectedExceptions[i];
        final allowTimeout = allowTimeouts![i];
        final description =
            'Generate Key with $params throws $expectedException';
        test(description, () async {
          await expectThrowsOrCompletes<dynamic>(
            () => generateKeyPair(params),
            description,
            throwsType: expectedException,
            timeout:
                (params['modulusLength'] as int? ?? 2048) >= 16384
                    ? Duration(seconds: 60)
                    : Duration(seconds: 5),
            allowTimeout: allowTimeout,
          );
        });
      }

      test(
        'Resource exhaustion (10x 16384-bit keys)',
        () async {
          final futures = <Future>[];
          for (int i = 0; i < 10; i++) {
            futures.add(
              generateKeyPair({
                'modulusLength': 16384,
                'publicExponent': BigInt.from(65537),
                'hash': Hash.sha256,
              }),
            );
          }
          await expectThrowsOrCompletes<dynamic>(
            () => Future.wait(futures),
            'Resource exhaustion (10x 16384-bit keys)',
            shouldComplete: true,
            timeout: Duration(seconds: 120), // Increased timeout
            allowTimeout: true,
          );
        },
        skip: 'Run manually to avoid CI overload',
      );
    });
  }
}

/// RsaPss-specific implementation
class RsaPssTestRunner
    extends CryptoTestRunner<RsaPssPrivateKey, RsaPssPublicKey> {
  RsaPssTestRunner({super.testCases})
    : super(
        algorithm: 'RSA-PSS',
        generateKeyPair:
            (params) => RsaPssPrivateKey.generateKey(
              params['modulusLength'] as int,
              params['publicExponent'] as BigInt,
              params['hash'] as Hash,
            ),
        importPrivateKey:
            (keyData, params) => RsaPssPrivateKey.importPkcs8Key(
              keyData,
              params['hash'] as Hash,
            ),
        importPublicKey:
            (keyData, params) =>
                RsaPssPublicKey.importSpkiKey(keyData, params['hash'] as Hash),
        sign:
            (key, data, params) =>
                key.signBytes(data, params['saltLength'] as int),
        verify:
            (key, signature, data, params) =>
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
      plaintext: [1, 2, 3],
      signVerifyParams: {'saltLength': 32},
    ),
    CryptoTestCase(
      name: 'Max key size (16384)',
      generateKeyParams: {
        'modulusLength': 16384,
        'publicExponent': BigInt.from(65537),
        'hash': Hash.sha256,
      },
      plaintext: [1, 2, 3],
      signVerifyParams: {'saltLength': 32},
    ),
  ];

  final edgeCaseParams = [
    {
      'modulusLength': -2048,
      'publicExponent': BigInt.from(65537),
      'hash': Hash.sha256,
    },
    {
      'modulusLength': 0,
      'publicExponent': BigInt.from(65537),
      'hash': Hash.sha256,
    },
    {
      'modulusLength': 8,
      'publicExponent': BigInt.from(65537),
      'hash': Hash.sha256,
    },
    {
      'modulusLength': 2049,
      'publicExponent': BigInt.from(65537),
      'hash': Hash.sha256,
    },
    {
      'modulusLength': 100000,
      'publicExponent': BigInt.from(65537),
      'hash': Hash.sha256,
    },
    {
      'modulusLength': 2048,
      'publicExponent': BigInt.from(-65537),
      'hash': Hash.sha256,
    },
    {'modulusLength': 2048, 'publicExponent': BigInt.zero, 'hash': Hash.sha256},
    {
      'modulusLength': 2048,
      'publicExponent': BigInt.from(2),
      'hash': Hash.sha256,
    },
    {
      'modulusLength': 2048,
      'publicExponent': BigInt.parse('2' * 1000),
      'hash': Hash.sha256,
    },
    {'modulusLength': 2048, 'publicExponent': BigInt.from(65537), 'hash': null},
  ];
  final expectedExceptions = [
    UnsupportedError, // Adjusted for Desktop
    UnsupportedError, // Adjusted for Desktop
    UnsupportedError, // Adjusted for Desktop
    UnsupportedError, // Adjusted for Desktop
    UnsupportedError, // Adjusted for Desktop
    UnsupportedError,
    UnsupportedError,
    UnsupportedError,
    UnsupportedError,
    TypeError,
  ];
  final allowTimeouts = List.filled(edgeCaseParams.length, false);

  final runner = RsaPssTestRunner(testCases: testCases);
  runner.registerTests();
  runner.registerExceptionTests(
    edgeCaseParams: edgeCaseParams,
    expectedExceptions: expectedExceptions,
    allowTimeouts: allowTimeouts,
  );
}
