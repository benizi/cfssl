// +build pkcs11
package pkcs11

import (
	"crypto"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/cloudflare/cfssl/config"
	cferr "github.com/cloudflare/cfssl/errors"
	"github.com/cloudflare/cfssl/helpers"
	"github.com/cloudflare/cfssl/log"
	"github.com/cloudflare/cfssl/signer"
	"github.com/cloudflare/cfssl/signer/local"

	"github.com/letsencrypt/pkcs11key"
)

func init() {
	signer.Register("pkcs11Signer", pkcs11Signer)
}

type pkcs11Config struct {
	Module  string `json:"module"`
	Token   string `json:"token"`
	PINFile string `json:"pinfile"`
}

func pkcs11Error(format string, params ...interface{}) error {
	msg := fmt.Sprintf(format, params...)
	log.Error(msg)
	err := errors.New(msg)
	return cferr.Wrap(cferr.PrivateKeyError, cferr.ParseFailed, err)
}

func pkcs11Signer(cfg map[string]string, policy *config.Signing) (signer.Signer, bool, error) {
	certFile := cfg["cert-file"]
	configFile := cfg["pkcs11-config"]

	if configFile == "" {
		return nil, false, nil
	}

	configBytes, err := helpers.ReadBytes(configFile)
	if err != nil {
		err = pkcs11Error("Failed to parse -pkcs11-config=%v: %s", configFile, err.Error())
		return nil, false, err
	}

	config := &pkcs11Config{}
	err = json.Unmarshal(configBytes, &config)
	if err != nil {
		err = pkcs11Error("Failed to unmarshal %v: %s", string(configBytes), err.Error())
		return nil, false, err
	}

	pinBytes, err := helpers.ReadBytes(config.PINFile)
	if err != nil {
		err = pkcs11Error("Failed to read PIN: %s", err.Error())
		return nil, false, err
	}

	pin := string(pinBytes)
	if pin == "" {
		return nil, false, errors.New("No PKCS#11 PIN present in " + config.PINFile)
	}

	caPEM, err := helpers.ReadBytes(certFile)
	if err != nil {
		return nil, false, err
	}

	caCert, err := helpers.ParseCertificatePEM(caPEM)
	if err != nil {
		return nil, false, err
	}

	pubkey, ok := caCert.PublicKey.(crypto.PublicKey)
	if !ok {
		return nil, false, errors.New("Certificate Public Key is not a crypto.PublicKey")
	}

	priv, err := pkcs11key.New(config.Module, config.Token, pin, pubkey)
	if err != nil {
		return nil, false, err
	}

	sigAlgo := signer.DefaultSigAlgo(priv)
	s, err := local.NewSigner(priv, caCert, sigAlgo, policy)
	return s, err == nil, err
}
