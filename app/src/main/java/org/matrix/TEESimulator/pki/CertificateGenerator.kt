package org.matrix.TEESimulator.pki

import android.hardware.security.keymint.Algorithm
import android.hardware.security.keymint.KeyPurpose
import android.os.Build
import android.util.Pair
import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.cert.Certificate
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.security.spec.RSAKeyGenParameterSpec
import java.util.Date
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.KeyUsage
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.matrix.TEESimulator.attestation.AttestationBuilder
import org.matrix.TEESimulator.attestation.AttestationConstants
import org.matrix.TEESimulator.attestation.KeyMintAttestation
import org.matrix.TEESimulator.config.ConfigurationManager
import org.matrix.TEESimulator.interception.keystore.KeyIdentifier
import org.matrix.TEESimulator.interception.keystore.shim.KeyMintSecurityLevelInterceptor
import org.matrix.TEESimulator.logging.SystemLogger

object CertificateGenerator {

    fun generateSoftwareKeyPair(params: KeyMintAttestation): KeyPair? {
        return runCatching {
                val (algorithm, spec) =
                    when (params.algorithm) {
                        Algorithm.EC -> "EC" to ECGenParameterSpec(params.ecCurveName)
                        Algorithm.RSA ->
                            "RSA" to
                                RSAKeyGenParameterSpec(params.keySize, params.rsaPublicExponent)
                        else ->
                            throw IllegalArgumentException(
                                "Unsupported algorithm: ${params.algorithm}"
                            )
                    }
                SystemLogger.debug("Generating $algorithm key pair with size ${params.keySize}")
                KeyPairGenerator.getInstance(algorithm, BouncyCastleProvider.PROVIDER_NAME)
                    .apply { initialize(spec) }
                    .generateKeyPair()
            }
            .onFailure { SystemLogger.error("Failed to generate software key pair.", it) }
            .getOrNull()
    }

    fun generateCertificateChain(
        uid: Int,
        subjectKeyPair: KeyPair,
        attestKeyAlias: String?,
        params: KeyMintAttestation,
        securityLevel: Int,
    ): List<Certificate>? {
        val challenge = params.attestationChallenge
        if (challenge != null && challenge.size > AttestationConstants.CHALLENGE_LENGTH_LIMIT)
            throw IllegalArgumentException(
                "Attestation challenge exceeds length limit (${challenge.size} > ${AttestationConstants.CHALLENGE_LENGTH_LIMIT})"
            )

        return runCatching {
                val keybox = getKeyboxForAlgorithm(uid, params.algorithm)

                val (signingKey, issuer, issuerCert) =
                    if (attestKeyAlias != null && Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                        getAttestationKeyInfo(uid, attestKeyAlias)?.let {
                            Triple(it.first, it.second, null as X509Certificate?)
                        } ?: Triple(
                            keybox.keyPair,
                            getIssuerFromKeybox(keybox),
                            keybox.certificates.firstOrNull() as? X509Certificate
                        )
                    } else {
                        Triple(
                            keybox.keyPair,
                            getIssuerFromKeybox(keybox),
                            keybox.certificates.firstOrNull() as? X509Certificate
                        )
                    }

                val leafCert =
                    buildCertificate(subjectKeyPair, signingKey, issuer, issuerCert, params, uid, securityLevel)

                if (attestKeyAlias != null) {
                    listOf(leafCert)
                } else {
                    listOf(leafCert) + keybox.certificates
                }
            }
            .onFailure { SystemLogger.error("Failed to generate certificate chain.", it) }
            .getOrNull()
    }

    fun generateAttestedKeyPair(
        uid: Int,
        alias: String,
        attestKeyAlias: String?,
        params: KeyMintAttestation,
        securityLevel: Int,
    ): Pair<KeyPair, List<Certificate>>? {
        return runCatching {
                SystemLogger.info(
                    "Generating new attested key pair for alias: '$alias' (UID: $uid)"
                )
                val newKeyPair =
                    generateSoftwareKeyPair(params)
                        ?: throw Exception("Failed to generate underlying software key pair.")

                val chain =
                    generateCertificateChain(uid, newKeyPair, attestKeyAlias, params, securityLevel)
                        ?: throw Exception("Failed to generate certificate chain for new key pair.")

                SystemLogger.info(
                    "Successfully generated new certificate chain for alias: '$alias'."
                )
                Pair(newKeyPair, chain)
            }
            .onFailure {
                SystemLogger.error("Failed to generate attested key pair for alias '$alias'.", it)
            }
            .getOrNull()
    }

    fun getIssuerFromKeybox(keybox: KeyBox) =
        X509CertificateHolder(keybox.certificates[0].encoded).subject

    private fun getKeyboxForAlgorithm(uid: Int, algorithm: Int): KeyBox {
        val keyboxFile = ConfigurationManager.getKeyboxFileForUid(uid)
        val algorithmName =
            when (algorithm) {
                Algorithm.EC -> "EC"
                Algorithm.RSA -> "RSA"
                else -> throw IllegalArgumentException("Unsupported algorithm ID: $algorithm")
            }
        return KeyBoxManager.getAttestationKey(keyboxFile, algorithmName)
            ?: throw Exception("Could not load keybox for UID $uid and algorithm $algorithmName")
    }

    private fun getAttestationKeyInfo(uid: Int, attestKeyAlias: String): Pair<KeyPair, X500Name>? {
        SystemLogger.debug("Looking for attestation key: uid=$uid alias=$attestKeyAlias")
        val keyId = KeyIdentifier(uid, attestKeyAlias)
        val keyInfo = KeyMintSecurityLevelInterceptor.generatedKeys[keyId]
        return if (keyInfo != null) {
            val certChain = CertificateHelper.getCertificateChain(keyInfo.response)
            if (!certChain.isNullOrEmpty()) {
                val issuer = X509CertificateHolder(certChain[0].encoded).subject
                Pair(keyInfo.keyPair, issuer)
            } else {
                null
            }
        } else {
            SystemLogger.warning(
                "Attestation key '$attestKeyAlias' not found in generated key cache."
            )
            null
        }
    }

    private fun buildKeyUsageFromPurposes(purposes: List<Int>): Int {
        var bits = 0
        for (purpose in purposes) {
            bits = bits or when (purpose) {
                KeyPurpose.SIGN -> KeyUsage.digitalSignature
                KeyPurpose.DECRYPT -> KeyUsage.dataEncipherment
                KeyPurpose.WRAP_KEY -> KeyUsage.keyEncipherment
                KeyPurpose.AGREE_KEY -> KeyUsage.keyAgreement
                KeyPurpose.ATTEST_KEY -> KeyUsage.keyCertSign
                else -> 0
            }
        }
        return bits
    }

    private fun buildCertificate(
        subjectKeyPair: KeyPair,
        signingKeyPair: KeyPair,
        issuer: X500Name,
        issuerCert: X509Certificate?,
        params: KeyMintAttestation,
        uid: Int,
        securityLevel: Int,
    ): Certificate {
        val subject = params.certificateSubject ?: X500Name("CN=Android Keystore Key")
        SystemLogger.debug("[CertGen] Subject: $subject")
        // Real TEEs use 25-30 year validity periods (per AOSP Beanpod KeyMaster observation)
        val THIRTY_YEARS_MS = 30L * 365 * 24 * 60 * 60 * 1000
        val leafNotAfter = issuerCert?.notAfter
            ?: Date(System.currentTimeMillis() + THIRTY_YEARS_MS)
        SystemLogger.debug("[CertGen] Validity: ${params.certificateNotBefore ?: Date()} to $leafNotAfter")

        val builder =
            JcaX509v3CertificateBuilder(
                issuer,
                params.certificateSerial ?: BigInteger.ONE,
                params.certificateNotBefore ?: Date(),
                params.certificateNotAfter ?: leafNotAfter,
                subject,
                subjectKeyPair.public,
            )

        // Add KeyUsage extension only if purposes map to valid bits
        val keyUsageBits = buildKeyUsageFromPurposes(params.purpose)
        if (keyUsageBits != 0) {
            builder.addExtension(Extension.keyUsage, true, KeyUsage(keyUsageBits))
            SystemLogger.debug("[CertGen] Added KeyUsage extension: bits=0x${keyUsageBits.toString(16)}")
        }

        // RFC 5280 Section 4.2.1.9: end-entity cert must not act as CA
        builder.addExtension(Extension.basicConstraints, true, BasicConstraints(false))
        SystemLogger.debug("[CertGen] Added BasicConstraints: CA=false")

        val extUtils = JcaX509ExtensionUtils()

        // RFC 5280 Section 4.2.1.2: SHA-1 hash of subject public key
        builder.addExtension(
            Extension.subjectKeyIdentifier,
            false,
            extUtils.createSubjectKeyIdentifier(subjectKeyPair.public)
        )
        SystemLogger.debug("[CertGen] Added SubjectKeyIdentifier (SKI)")

        // RFC 5280 Section 4.2.1.1: links certificate to issuer's signing key
        if (issuerCert != null) {
            builder.addExtension(
                Extension.authorityKeyIdentifier,
                false,
                extUtils.createAuthorityKeyIdentifier(issuerCert)
            )
            SystemLogger.debug("[CertGen] Added AuthorityKeyIdentifier (AKI) from issuer")
        }

        builder.addExtension(
            AttestationBuilder.buildAttestationExtension(params, uid, securityLevel)
        )

        val signerAlgorithm =
            when (params.algorithm) {
                Algorithm.EC -> "SHA256withECDSA"
                Algorithm.RSA -> "SHA256withRSA"
                else -> throw IllegalArgumentException("Unsupported algorithm: ${params.algorithm}")
            }
        val contentSigner =
            JcaContentSignerBuilder(signerAlgorithm)
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .build(signingKeyPair.private)

        return JcaX509CertificateConverter().getCertificate(builder.build(contentSigner))
    }
}
