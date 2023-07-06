Why does CyrusSasl store plaintext passwords in its databases?
--------------------------------------------------------------

To operate with the CRAM-MD5 and SCRAM mechanisms, Cyrus SASL 
stores plaintext versions of the passwords in its secret database (an 
AuxpropPlugin). 

This is typically regarded as insecure practice, however the alternative 
is not much better. For CRAM-MD5 and SCRAM to function, they must 
have a plaintext equivalent locally in order to confirm the hash that 
actually goes across a wire. This, if these equivalents were 
compromised, it is trivially easy for an attacker to have access to any 
account on the system. 
