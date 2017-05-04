package gssapi

/*
#cgo LDFLAGS: -lsasl2
#include <sasl/sasl.h>
#include <stdlib.h>
*/
import "C"

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"unsafe"
)

// sendToken send token to service
func sendToken(conn io.Writer, buf []byte) error {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, uint32(len(buf)))
	_, err := conn.Write(b)
	if err != nil {
		return err
	}
	conn.Write(buf)
	if err != nil {
		return err
	}
	return nil
}

// recvToken recive from a token from service
func recvToken(conn io.ReadWriter) ([]byte, error) {
	b := make([]byte, 4)
	_, err := conn.Read(b)
	if err != nil {
		return b, err
	}

	size := binary.BigEndian.Uint32(b)
	buf := make([]byte, size)
	_, err = conn.Read(buf)

	return buf, err
}

func saslErr(ctx *C.sasl_conn_t) error {
	if ctx == nil {
		return nil
	}
	str := C.GoString(C.sasl_errdetail(ctx))
	return errors.New(str)
}

// GssAuth complete handling of establishing SASL/Kerberos Authentication
func GssAuth(rw io.ReadWriter, service string, realm string) error {
	errCode := C.sasl_client_init(nil)
	if errCode != C.SASL_OK {
		return fmt.Errorf("sasl_client_init failed")
	}

	var ctx *C.sasl_conn_t

	cservice := C.CString(service)
	defer C.free(unsafe.Pointer(cservice))

	crealm := C.CString(realm)
	defer C.free(unsafe.Pointer(crealm))

	errCode = C.sasl_client_new(cservice,
		crealm,
		nil,
		nil,
		nil,
		C.uint(0),
		&ctx)

	if errCode != C.SASL_OK {
		return fmt.Errorf("sasl_client_new cannot establish new context, %v", saslErr(ctx))
	}

	defer C.sasl_dispose(&ctx)

	var out *C.char
	var outlen C.uint
	mech := C.CString("GSSAPI")
	defer C.free(unsafe.Pointer(mech))

	errCode = C.sasl_client_start(ctx,
		mech,
		nil,
		&out,
		&outlen,
		nil)

	if errCode != C.SASL_OK {
		return fmt.Errorf("sasl_client_start failed, %v", saslErr(ctx))
	}
	defer C.sasl_client_done()

	// send initial requestToken
	reqtoken := C.GoBytes(unsafe.Pointer(out), C.int(outlen))
	err := sendToken(rw, reqtoken)
	if err != nil {
		return fmt.Errorf("send token to service failed, %v", err)
	}

	for errCode == C.SASL_CONTINUE {
		reptoken, err := recvToken(rw)
		if err != nil {
			return fmt.Errorf("recive token from service failed, %v", err)
		}

		in := unsafe.Pointer(C.CString(string(reptoken)))
		defer C.free(in)

		errCode = C.sasl_client_step(ctx,
			(*C.char)(in),
			C.uint(len(reptoken)),
			nil,
			&out,
			&outlen)

		reqtoken = C.GoBytes(unsafe.Pointer(out), C.int(outlen))
		err = sendToken(rw, reqtoken)
		if err != nil {
			return fmt.Errorf("send token to service failed, %v", err)
		}
	}

	if errCode != C.SASL_OK {
		return fmt.Errorf("Authentication handshake was not completed, %v", saslErr(ctx))
	}

	return nil
}
