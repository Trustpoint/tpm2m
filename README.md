TPM2M Certificate Handling Library
==================================
---

The TPM2M library provides functionality to work with M2M certificates as defined by the IETF draft
found at <https://tools.ietf.org/html/draft-ford-m2mcertificate-00>.

M2M certificates are similar to X.509 certificates in function, but are designed to be smaller and
more suitable for machine-to-machine environments and other constrained environments. M2M
certificates can be as much as [40% smaller][IETF_draft] in size to traditional X.509 certificates.
M2M certificates are designed to work with [Elliptic Curve Cryptography (ECC)][ECC_Wikipedia]
primitives such as the [Elliptic Curve Digital Signature Algorithm (ECDSA)][ECDSA_Wikipedia] and
[Elliptic Curve Qu-Vanstone (ECQV) implicit certificates][ECQV_SEC4], which are significantly
smaller and more efficient to work with than traditional [RSA][RSA_Wikipedia]-based X.509
certificates. This allows the use of Public Key Infrastructure based solutions in environments where
not previously possible. Through the use of M2M certificates, high levels of security can be
achieved in constrained environments where this has previously been impossible due to the size of
X.509 certificates and the resources required for RSA-based primitives.

Features
--------

The TPM2M library provides the following main features:

* M2M certificate construction given all the necessary information
* M2M certificate chain construction
* Encoding to DER ASN.1 format
* Decoding from DER ASN.1 format
* M2M certificate verification
* M2M certificate chain verification
* ECQV public key reconstruction

Language-specific Versions
--------------------------

The follow language specific implementations of the library are available:

* [Java](https://github.com/Trustpoint/tpm2m/tree/master/java) - under the `java/` subdirectory

See the appropriate subdirectory for documentation specific to each language-specific version.

License
-------

> Copyright 2016 TrustPoint Innovation Technologies, Ltd.
>
> Licensed under the Apache License, Version 2.0 (the "License");
> you may not use this file except in compliance with the License.
> You may obtain a copy of the License at
>
> <http://www.apache.org/licenses/LICENSE-2.0>
>
> Unless required by applicable law or agreed to in writing, software
> distributed under the License is distributed on an "AS IS" BASIS,
> WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
> See the License for the specific language governing permissions and
> limitations under the License.

Contributing
------------

In order to clarify the intellectual property license granted with Contributions from any person or
entity, TrustPoint Innovation Technologies, Ltd. ("TrustPoint") must have a Contributor License
Agreement ("CLA") on file that has been signed by each Contributor, indicating agreement to the
license terms below. This license is for your protection as a Contributor as well as the protection
of TrustPoint; it does not change your rights to use your own Contributions for any other purpose.

There are two forms of the CLA, one for individuals and one for corporate entities. The Individual
CLA can be found in [iCLA.md](https://github.com/Trustpoint/tpm2m/tree/master/iCLA.md).
The Corporate CLA can be found in
[cCLA.md](https://github.com/Trustpoint/tpm2m/tree/master/cCLA.md). If you wish to contribute to the
project, please complete the appropriate form of the CLA and forward to TrustPoint.

Support
-------

Please post all support inquiries to the [Issues page](https://github.com/Trustpoint/tpm2m/issues).
Alternatively you can contact TrustPoint at <contact@trustpointinnovation.com>.

[IETF_draft]: https://tools.ietf.org/html/draft-ford-m2mcertificate-00 "Internet-Draft - The M2M Public Key Certificate Format"
[ECC_Wikipedia]: https://en.wikipedia.org/wiki/Elliptic_curve_cryptography "Wikipedia - Elliptic Curve Cryptography"
[ECDSA_Wikipedia]: https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm "Wikipedia - Elliptic Curve Digital Signature Algorithm"
[ECQV_SEC4]: http://www.secg.org/sec4-1.0.pdf "SEC 4: Elliptic Curve Qu-Vanstone Implicit Certificate Scheme (ECQV)"
[RSA_Wikipedia]: https://en.wikipedia.org/wiki/RSA_(cryptosystem) "RSA (cryptosystem)"
