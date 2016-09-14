TPM2M Certificate Handling Java Library
=======================================
---

The TPM2M Java library provides a java.security compliant implmentation for working with M2M
certificates. Specifically, it provides implementations of the following classes with support for
M2M certificates:

* `java.security.cert.Certificate`
* `java.security.cert.CertificateFactorySpi`
* `java.security.cert.CertPath`
* `java.security.cert.CertPathValidatorSpi`

Dependencies
------------

The TPM2M Java library makes use of the
[Legion of Bouncy Castle Java cryptography APIs][BouncyCastle]. These libraries are licensed as
follows:

> Please note this should be read in the same way as the MIT license.
>
> **LICENSE**
>
> Copyright (c) 2000 - 2016 The Legion of the Bouncy Castle Inc. (<https://www.bouncycastle.org>)
>
> Permission is hereby granted, free of charge, to any person obtaining a copy of this software and
> associated documentation files (the "Software"), to deal in the Software without restriction,
> including without limitation the rights to use, copy, modify, merge, publish, distribute,
> sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is
> furnished to do so, subject to the following conditions:
>
> The above copyright notice and this permission notice shall be included in all copies or
> substantial portions of the Software.
>
> THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT
> NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
> NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
> DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT
> OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

Building
--------

The TPM2M Java library is built using Gradle and the Java 1.6 JDK. Ensure that the `JAVA_HOME`
environment variable contains the location of a Java 1.6 JDK `home/` directory. From the `java/`
directory, run the following command from a terminal to build:

> On Unix/Linux/Mac OS:
> `./gradlew build`
>
> On Windows:
> `gradlew.bat build`

The built jar file can be found in the `java/build/libs/` folder.

Documentation
-------------

The TPM2M Java library documentation is available in JavaDoc form in the codebase. To build the
JavaDoc files, run the following command in a terminal from the `java` folder:

> On Unix/Linux/Mac OS:
> `./gradlew javadoc`
>
> On Windows:
> `gradlew.bat javadoc`

The built JavaDoc files can be found in the `java/build/docs/javadoc/` folder.

[BouncyCastle]: http://www.bouncycastle.org/java.html "The Legion of Bouncy Castle"
