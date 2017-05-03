package gssapi

/*
#cgo LDFLAGS: -lgssapi_krb5 -lkrb5 -lk5crypto -lcom_err
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gssapi/gssapi.h>
#include <gssapi/gssapi_generic.h>
#include <gssapi/gssapi_krb5.h>

#define GSS_ERRBUF_SIZE         512

typedef struct {
    gss_ctx_id_t     context;
    gss_name_t       server_name;
	gss_cred_id_t    client_creds;
    long int         gss_flags;
    char*            response;
} gss_client_state;

void get_gss_error(OM_uint32 err_maj, char *buf_maj, OM_uint32 err_min, char *buf_min)
{
    OM_uint32 maj_stat, min_stat;
    OM_uint32 msg_ctx = 0;
    gss_buffer_desc status_string;

    do {
        maj_stat = gss_display_status(
            &min_stat,
            err_maj,
            GSS_C_GSS_CODE,
            GSS_C_NO_OID,
            &msg_ctx,
            &status_string
        );
        if (GSS_ERROR(maj_stat)) {
            break;
        }
        strncpy(buf_maj, (char*) status_string.value, GSS_ERRBUF_SIZE);
        gss_release_buffer(&min_stat, &status_string);

        maj_stat = gss_display_status(
            &min_stat,
            err_min,
            GSS_C_MECH_CODE,
            GSS_C_NULL_OID,
            &msg_ctx,
            &status_string
        );
        if (! GSS_ERROR(maj_stat)) {
            strncpy(buf_min, (char*) status_string.value, GSS_ERRBUF_SIZE);
            gss_release_buffer(&min_stat, &status_string);
        }
    } while (!GSS_ERROR(maj_stat) && msg_ctx != 0);
}

*/
import "C"

import (
	"errors"
	"unsafe"
)

// Context Kerberos GSSAPI Client Context
type Context struct {
	state *C.gss_client_state
}

// Returns the last major/minor GSSAPI error messages
func gssError(majStat, minStat C.OM_uint32) error {
	bufMaj := (*C.char)(C.calloc(C.GSS_ERRBUF_SIZE, 1))
	bufMin := (*C.char)(C.calloc(C.GSS_ERRBUF_SIZE, 1))
	defer C.free(unsafe.Pointer(bufMaj))
	defer C.free(unsafe.Pointer(bufMin))

	C.get_gss_error(majStat, bufMaj, minStat, bufMin)
	return errors.New(C.GoString(bufMaj) + " - " + C.GoString(bufMin))
}

// Init a context for Kerberos GSSAPI client-side authentication.
// service is the client principal in the form "user@realm".
func Init(service string) (*Context, error) {
	cservice := C.CString(service)
	defer C.free(unsafe.Pointer(cservice))

	var majStat C.OM_uint32
	var minStat C.OM_uint32
	var nameToken C.gss_buffer_desc

	var state C.gss_client_state
	state.gss_flags = C.GSS_C_MUTUAL_FLAG | C.GSS_C_SEQUENCE_FLAG

	// Import server name first
	nameToken.length = C.strlen(cservice)
	nameToken.value = unsafe.Pointer(cservice)

	majStat = C.gss_import_name(&minStat,
		&nameToken,
		C.GSS_C_NT_USER_NAME,
		&state.server_name)

	if majStat != 0 {
		return nil, gssError(majStat, minStat)
	}

	majStat = C.gss_acquire_cred(&minStat,
		state.server_name,
		C.GSS_C_INDEFINITE,
		nil, // GSS_C_NO_OID_SET,
		C.GSS_C_INITIATE,
		&state.client_creds,
		nil,
		nil)

	if majStat != 0 {
		C.gss_release_name(&minStat, &state.server_name)
		return nil, gssError(majStat, minStat)
	}

	return &Context{state: &state}, nil
}

// Step processes a single GSSAPI client-side step using the supplied server data.
// retrun param :
// 1 []byte: token will send to serivce
// 2 bool, need continue
// 3 error, occurs a error
func (c *Context) Step(challenge []byte) ([]byte, bool, error) {
	var majStat C.OM_uint32
	var minStat C.OM_uint32
	var inputToken C.gss_buffer_desc
	var outputToken C.gss_buffer_desc

	// Always clear out the old response
	if c.state.response != nil {
		C.free(unsafe.Pointer(c.state.response))
		c.state.response = nil
	}

	// If there is a challenge (data from the server) we need to give it to GSS
	if challenge != nil {
		cchallenge := C.CString(string(challenge))
		defer C.free(unsafe.Pointer(cchallenge))
		inputToken.value = unsafe.Pointer(cchallenge)
		inputToken.length = (C.size_t)(len(challenge))
	}

	// Do GSSAPI step
	majStat = C.gss_init_sec_context(
		&minStat,
		c.state.client_creds,
		&c.state.context,
		c.state.server_name,
		nil, // GSS_C_NO_OID,
		C.OM_uint32(c.state.gss_flags),
		0,
		nil, // GSS_C_NO_CHANNEL_BINDINGS,
		&inputToken,
		nil,
		&outputToken,
		nil,
		nil)

	ctu := false
	if majStat == C.GSS_S_CONTINUE_NEEDED {
		ctu = true
	}
	if majStat != C.GSS_S_COMPLETE && majStat != C.GSS_S_CONTINUE_NEEDED {
		return nil, ctu, gssError(majStat, minStat)
	}

	if outputToken.length > 0 {
		gbytes := C.GoBytes(unsafe.Pointer(outputToken.value), (_Ctype_int)(outputToken.length))
		majStat = C.gss_release_buffer(&minStat, &outputToken)
		return gbytes, ctu, nil
	}

	return nil, ctu, nil
}

// Close to free all object memory
func (c *Context) Close() {
	var majStat C.OM_uint32
	var minStat C.OM_uint32

	if c.state.context != nil { // C.GSS_C_NO_CONTEXT
		majStat = C.gss_delete_sec_context(
			&minStat,
			&c.state.context,
			nil) //GSS_C_NO_BUFFER
	}

	if c.state.server_name != nil { //C.GSS_C_NO_NAME
		majStat = C.gss_release_name(&minStat, &c.state.server_name)
	}

	if c.state.client_creds != nil && // C.GSS_C_NO_CREDENTIAL
		C.long(c.state.gss_flags&C.GSS_C_DELEG_FLAG) != 0 {
		majStat = C.gss_release_cred(&majStat, &c.state.client_creds)
	}

	if c.state.response != nil {
		C.free(unsafe.Pointer(c.state.response))
		c.state.response = nil
	}
}
