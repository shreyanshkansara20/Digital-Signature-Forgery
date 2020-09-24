# Digital-Signature-Forgery-by-Exploiting-python-RSA-Vulnerability  -  CVE-2016-1494

# CVE-2016-1494
The verify function in the RSA package for Python (Python-RSA) before 3.3 allows attackers to spoof signatures with a small public exponent via crafted signature padding, aka a BERserk attack.

# Description
This python script basically exploits the vulnerability CVE-2016-1494 found in Python-RSA versions below 3.3. I downgraded my python-rsa version to 3.2 and was successfully able to forge the digital signature for the public key component 3.

The verfiy function of python-rsa module didn't check the padding in the way it should check which resulted in the vulnerability. 

# References
https://nvd.nist.gov/vuln/detail/CVE-2016-1494

https://blog.filippo.io/bleichenbacher-06-signature-forgery-in-python-rsa/




