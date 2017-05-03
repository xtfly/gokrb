# GoKrb

A go wrapper for Kerberos.

Currently the implemention:  
- Client side APIs that supports authentication to service that implement GSSAPI using Kerberos 5.

Note: It is developing...

# Usage

Note: You need to install the krb5-libs packages and gcc into your OS,
like this in Archlinux:

    $ sudo pacman -S krb5
    $ sudo pacman -S gcc

Install this package using go tools:

    $ go get github.com/xtfly/gokrb

To run you must have a valid Kerberos setup on the run machine
and you should ensure that you have valid Kerberos tickets:

    $ export KRB5_CONFIG=/path/to/krb5.conf
    $ kinit -kt "/path/to/your.keytab" "kafka/hadoop.com@HADOOP.COM"
    $ klist


Example Kerberos client authentication to service:

    package main

    import (
        "github.com/xtfly/gokrb"
        "github.com/xtfly/gokrb/gssapi"
    )

    func auth(conn io.ReadWriter) {
        ctx, err := gssapi.Init("kafka/hadoop.com@HADOOP.COM")
        if err != nil {
            println("Init error=>", err)
            return 
        }
        defer ctx.Close()

        // firstly create a token
        t, ctu, err := ctx.Step(nil)
        if err != nil {
            println("Step error=>", err)
            return 
        }

        for ctu {
            err = gokrb.SendToken(conn, t)
            if err != nil {
                println("SendToken error=>", err)
                return 
            }

            t, err := gokrb.RecvToken(conn)
            if err != nil {
                println("SendToken error=>", err)
                return 
            }

            t, err = ctx.Step(t)
            if err != nil {
                println("Step error=>", err)
                return 
            }

            err = gokrb.SendToken(conn, t)
            if err != nil {
                println("SendToken error=>", err)
                return 
            }
        }
    }

Note: if the krb5 is not install in /usr/lib64 and /usr/include, you need set follow environment variables:

    $ export CGO_CFLAG=-I/path/to/include
    $ export CGO_LDFLAG=-L/path/to/lib
    $ export LD_LIBRARY_PATH=/path/to/lib

# License

Gorkb is released under the MIT License. See the LICENSE file.

