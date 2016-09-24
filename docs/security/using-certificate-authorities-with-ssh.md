---
author:
    name: Lewin Bormann
    email: lbo@spheniscida.de
description: 'Use certificates to scale up SSH public key authentication'
keywords: 'ssh,pki,secure shell'
license: '[CC BY-ND 4.0](https://creativecommons.org/licenses/by-nd/4.0)'
alias: ['security/ssh-certs']
published: ''
title: Use SSH Certificates for Secure Scalable SSH Authentication
---

While [Public Key authentication](use-public-key-authentication-with-ssh) provides good security
already, managing and distributing your public keys can be tedious and chaotic. By using
certificates that are signed by a trusted CA (Certificate Authority), access management becomes
easier.

## Intro to SSH Certificates

If you haven't already, you should probably first read the [SSH Public
Key](use-public-key-authentication-with-ssh) guide. If you are owning one or two servers, and only
have very few people using those machines, using individual public keys and putting them on the
machines works fine.

But what if you suddenly have to manage two dozen machines with fifty people
needing access -- some to the same account, some only to some machines...? At this point, putting
all authorized person's keys into the `authorized_keys` file on appropriate servers for appropriate
accounts is... complicated.

This guide explains how to set up a PKI (Public Key Infrastructure) with a CA (Certificate
Authority) that signs your users' keys and is trusted by the machines that your users want to log
into. It also shows how, conversely, you can use the trusted CA to authenticate machines to users, so
that users know that they're connecting to the right machines!

## Certificates

Luckily, OpenSSH supports certificates. A certificate is a normal SSH public key that you already
know from the SSH Public Key guide; however, it has some additional information associated with it:

* A serial number;
* A validity period;
* A list of *principals*;
* A list of *critical options*;
* A list of *extensions*;
* The key fingerprint of the signing CA;
* And finally a signature by that CA (over the hash of all information).

While your normal key files are named `id_rsa` (private RSA key) and `id_rsa.pub` (public RSA key),
certificates are stored in files named `id_rsa-cert.pub` (or `id_ecdsa-cert.pub`, depending on the
key algorithm).

## Concept: How Certificates are Used

In principle, certificates can be used both for authenticating servers and
authenticating/authorizing clients; in this guide, we will first focus on configuring
servers to grant access to users based on certificates.

> If you're not yet familiar with it, it's recommended that you read up on [Public Key
> Cryptography](https://en.wikipedia.org/wiki/Public_Key_Cryptography)

If a server is configured to trust a certain CA, it can trust all keys signed by that CA; because it
knows that at some point, you entered the CA password and made the decision to trust that key.
Because the CA's signature is made over both key and attached information, the server can also be
sure that all other information on the key is valid, and can then give privileges to users based on
that information.

The client proves that it is actually authorized to use the certificate by signing a challenge (some
arbitrary bytes sent by the server) with its private key; the server can verify the signature using
the public key contained in the certificate.

Conversely, a client doesn't know if a server that it is connecting to is authentic. By presenting a
certificate that has been signed by a CA that the client trusts and signing a challenge sent by the 
client with the server's private key, the client can be sure that the server is trustable.

This means, for example, that you don't need to confirm the authenticity of remote hosts anymore:

```
The authenticity of host 'host.example.net (192.0.2.32)' can't be established.
RSA key fingerprint is SHA256:85Of5qSwAdERHsXteLNm3M6lCaPFwgq/6T35LcrmDaA.
RSA key fingerprint is MD5:ac:17:9f:43:cd:80:9e:ae:83:5f:13:dc:3e:57:04:2d.
Are you sure you want to continue connecting (yes/no)? 
```

## Creating a CA and Signing Keys

A CA key is just an ordinary SSH key. You can generate one by running the following command:

    ssh-keygen -f ca_key

This will write your CA RSA private key to `ca_key`, and the public key to `ca_key.pub`. It is
important that you choose a strong password, as this key will protect access to all your machines!
You can also use `-b 4096` in order to get a stronger key.

We'll assume that you already own an SSH key pair at `~/.ssh/id_rsa`. If you are using ECDSA keys or
your keys are differently named, just change the file names in the following commands.

To sign your existing keypair and create a certificate, run

    ssh-keygen -s ca_key -I my-key-identity -n princ1,princ2 -V +52w -Z 1 -O permit-pty,permit-x11-forwarding -z 123 ~/.ssh/id_rsa

The result of this command is a certificate at `~/.ssh/id_rsa-cert.pub`. Here's an explanation of
the options:

* `-s` specifies the CA key to use.
* `-I` specifies the identity of the key. It will show up in server logs, and can be used for key
  revocation.
* `-n` is a list of principals. See the section on *Per-User Authentication* on what this means!
* `-V` specifies how long the certificate should be valid. Examples: `+1w` (valid one week from
  now), `-1w:+5w` (valid from one week ago to in five weeks), `-1h:+24h` (valid from one hour ago to
  in 24 hours)
* `-O` specifies a list of options that the certificate authorizes a user to do. Refer to what `man
    ssh-keygen` says on the `-O` option for a full list.
* `-z` specifies a *serial number*; it will appear in logs and can, like the identity, be used for
  key revocation.

Congratulations! You now have a valid certificate. If you want, you can take a look at it by running

    ssh-keygen -L -f ~/.ssh/id_rsa-cert.pub

## Configuring a Server to Accept Certificates

### Per-User Authentication

> Note: This section is here for completeness; it's not that different from just using normal public
> keys for authentication.

To authorize any user with a certificate signed by your CA to log in to an account on your server,
copy the public CA key to the `~/.ssh/authorized_keys` file of the account to log into.

However, because it is a CA key, you have to prefix that line with `cert-authority`. It should look
like this:

    cert-authority ecdsa-sha2-nistp521 AAAAE2VjZHNhLXNoYTItbmlzdHA1MjEAAAAIbmlzdHA1MjE...

Now anyone with a certificate signed by your CA can sign in.

Well, almost anyone -- the list of principals on the certificate of that user has to contain the
user name of the account! That's what the `-n` option of `ssh-keygen` is for; a *principal* is
basically a scope that a certificate is valid for. For example, you might want to give yourself
superuser power *everywhere*, and sign your certificate with, among others, the principal
*superroot*.

To make `sshd` accept your certificate for any user account, you have to modify the
`authorized_keys` file like this:

    cert-authority,principals="superroot" ecdsa-sha2-nistp521 AAAAE2VjZHNhLXNoYTItbmlzdHA1MjEAAAAIbmlzdHA1MjE...

> sshd is a bit picky; if there's some typo or syntax error, it will just ignore the
> `authorized_keys` file.

Now this is a bit boring; after all, you could achieve the same thing using normal public keys.
Continue reading to find out how to make it a bit more scalable!

### General Client Authentication

Configuring an `sshd` to accept certificates is quite easy; simply paste the public CA key into a
file like `/etc/ssh/trusted_ca_keys`, and add the following entry to `/etc/ssh/sshd_config`:

    TrustedUserCAKeys /etc/ssh/trusted_ca_keys

After a restart (`systemctl restart sshd`), `sshd` will accept certificates signed by that CA to
sign in into any user account that is contained in the list of principals. For example, if you want
your webmaster to only be able to log in as the web user, give them a principal of `www-data` (or
whatever your web server runs as). You can give your system administrators the `root` principal to
be able to log in as root (except if you have `PermitRootLogin` set to `no`).

Once this is setup, the server will log something like this once you log in:

```
Sep 24 20:17:35 fedora sshd[21839]: Accepted publickey for lbo from <IP> port 33402 ssh2: ECDSA-CERT ID <Client Certificate Identity> (serial 4) CA ECDSA SHA256:aX92/3uh5e0/GYoYvwC4eD612URo1MCz6OnARGPqwgU
```


On top of this, you can set the `AuthorizedPrincipalsFile` option to the path of a file that
contains valid principals. If you set it to one file, e.g. `/etc/ssh/authorized_principals`, any
certificate with a principal that appears in that file is able to log in to *any* account.

However, you can also set the option to a path like `%h/.ssh/principals`; `%h` will be replaced by
the home directory of the user that someone tries to log in as. Based on this, you can create a
quite powerful hierarchy of principals that are allowed to log in to different accounts.

> Note: If you set the `AuthorizedPrincipalsFile` option, the standard behavior of "user name has to
> appear in principals list" doesn't apply anymore.

You can make even more powerful authorization decisions using the `AuthorizedPrincipalsCommand`
option. If you set it to a command (`%u` being replaced by the user trying to log in, and `%h` by
the home directory), you can make dynamic decisions, for example backed by LDAP or Active Directory,
on whether to allow the user to log in. The command should, when executed, print a list of allowed
principals to standard output. For example, to simulate standard behavior (that is, let any user
log in if the user name appears in the list of principals), set the following option in
`sshd_config`:

    AuthorizedPrincipalsCommandUser root
    AuthorizedPrincipalsCommand "/bin/echo %u"

(not that this would make much sense)

## Configuring a Client to Accept Host Certificates

To configure your SSH server with a host certificate, you must first again sign its key; in this
case, the host key. Important: the `-h` option telling `ssh-keygen` that it's a host key!

    # ssh-keygen -s /path/to/ca_key -I `hostname` -h /etc/ssh/ssh_host_rsa_key

Then, in order to make the serve send that certificate (`/etc/ssh/ssh_host_rsa_key-cert.pub`), add
the following line to `/etc/ssh/sshd_config`:

    HostCertificate /etc/ssh/ssh_host_rsa_key-cert.pub

> Note: While you will probably find several host keys (for RSA, ECDSA, Ed25519), it is enough to
> only generate a certificate for one of the keys. SSH clients will accept the certificate
> regardless of which key type the user actually uses.

And finally, in order for your SSH client to recognize severs with that certificate as trustworthy,
add the following line to your `~/.ssh/known_hosts`:

    @cert-authority *.example.com ecdsa-sha2-nistp521 AAAAE2VjZHNhLXNoYTItbmlzdHA1MjEAAA...

The first part is a so-called *marker*, identifying the key as CA key; the second part is a pattern
describing all hosts to accept certificates signed by the CA from; and the third part is, you
guessed it, the public CA key.

From now on, your client should not ask you the pesky `Are you sure you want to continue connecting
(yes/no)?` question anymore if you're connecting to a server you know. You can see the inner
workings when enabling debug output on your SSH client:

```
debug1: Server host certificate: ssh-rsa-cert-v01@openssh.com
SHA256:L5AZVU9oz97zIN2i7tFoNaC+HOjv1TlFm8/7rMHShSQ, serial 5 ID "my_linode_server" CA ecdsa-sha2-nistp521
SHA256:mJcstaUHXfwI0Ug+sLM+fAX6wQtX1iWmkiWG6Mwf9FE valid forever
debug1: Host 'my.linode.example.com' is known and matches the RSA-CERT host certificate.
```

> While this doesn't bring you much if you configure all your servers by hand, it certainly is
> useful to give your coworkers an increased sense of security when they want to log onto different
> machines that they may not have logged into before.

## Revoking Keys and Certificates

Finally, you should think about the case that a certificate leaks, or an employee leaves. You should
revoke the certificate, and thus make it unusable, right?

You can generate a KRL (Key Revocation List) using `ssh-keygen`:

    $ ssh-keygen -k new_krl_file -u -s /path/to/ca_key -
    id: some-key-identity
    serial: 12-18
    sha1: ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDw72IP7J8CsqRPi...
    key: ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDw72IP7J8CsqRPi...
    [Ctrl-D]

> `sha1` will revoke a key by its SHA1 sum, while `key` stores the entire key in the KRL.

This will generate a KRL that contains the key with `some-key-identity` and all certificates with
serial numbers between 12 and 18. Additionally, serves using that KRL will refuse clients presenting
the specified key.

In order to use the KRL on your server, just save the KRL on your server and add the following
option to `/etc/ssh/sshd_config`:

    RevokedKeys /path/to/your.krl

