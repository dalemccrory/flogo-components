package sftp

import (
	"fmt"
	"github.com/TIBCOSoftware/flogo-lib/core/activity"
	"github.com/TIBCOSoftware/flogo-lib/logger"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
	"io"
	"os"
	"strings"
	"syscall"
)

// log is the default package logger
var log = logger.GetLogger("activity-tibco-sftp")

const (
	methodGET    = "GET"
	methodPUT    = "PUT"
	methodRENAME = "RENAME"
	methodDELETE = "DELETE"

	ivHost        = "host"
	ivPort        = "port"
	ivUser        = "user"
	ivPassword    = "password"
	ivMethod      = "method"
	ivSource      = "source"
	ivDestination = "destination"

	ovResult = "result"
)

var validMethods = []string{methodGET, methodPUT, methodRENAME, methodDELETE}

// SFTPActivity is a stub for SFTP Activity implementation
// inputs : {host,port,user,password,method,source,destination}
// outputs: {result}
type SFTPActivity struct {
	metadata *activity.Metadata
}

// NewActivity creates a new activity of SFTP
func NewActivity(metadata *activity.Metadata) activity.Activity {
	return &SFTPActivity{metadata: metadata}
}

// Metadata implements activity.Activity.Metadata
func (a *SFTPActivity) Metadata() *activity.Metadata {
	return a.metadata
}

// Eval implements activity.Activity.Eval
func (a *SFTPActivity) Eval(context activity.Context) (done bool, err error) {

	host := strings.ToUpper(context.GetInput(ivHost).(string))
	port := context.GetInput(ivPort).(int)
	user := strings.ToUpper(context.GetInput(ivUser).(string))
	password := strings.ToUpper(context.GetInput(ivPassword).(string))
	method := strings.ToUpper(context.GetInput(ivMethod).(string))
	source := strings.ToUpper(context.GetInput(ivSource).(string))
	destination := strings.ToUpper(context.GetInput(ivDestination).(string))

	//TODO -> create function to create ssh/sftp client
	//TODO -> reuse ssh connection/sftp client after processing and evict after no minimum usage
	//Create SSH Connection and SFTP Client - START
	var auths []ssh.AuthMethod
	auths = append(auths, ssh.Password(password))
	config := ssh.ClientConfig{
		User:            user,
		Auth:            auths,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	addr := fmt.Sprintf("%s:%d", host, port)
	log.Debugf("Dialing SSH Connection: host=[%s] port=[%v] user=[%s]\n", host, port, user)
	conn, err := ssh.Dial("tcp", addr, &config)
	if err != nil {
		log.Errorf("unable to connect: %v", err)
		return true, err
	}
	defer conn.Close()
	log.Debugf("SSH Connected")
	log.Debugf("Creating SFTP Client")
	c, err := sftp.NewClient(conn)
	if err != nil {
		log.Errorf("unable to create sftp client: %v", err)
		return true, err
	}
	defer c.Close()
	log.Debugf("SFTP Client Created")
	//Create SSH Connection and SFTP Client - END

	switch method {
	case methodGET:
		log.Debugf("method=%v source=%s destination=%s", methodGET, source, destination)
		r, err := c.Open(source)
		if err != nil {
			log.Errorf("unable to open source file: %v", err)
			return true, err
		}
		defer r.Close()
		w, err := os.OpenFile(destination, syscall.O_WRONLY, 0600)
		if err != nil {
			log.Errorf("unable to open destination file: %v", err)
			return true, err
		}
		defer w.Close()
		n, err := io.Copy(w, r)
		if err != nil {
			log.Errorf("unable to open copy: %v", err)
			return true, err
		}
		context.SetOutput(ovResult, n)
		return true, nil

	case methodPUT:
		log.Debugf("method=%v source=%s destination=%s", methodPUT, source, destination)
		r, err := os.Open(source)
		if err != nil {
			log.Errorf("unable to open source file: %v", err)
			return true, err
		}
		defer r.Close()
		w, err := c.OpenFile(destination, syscall.O_WRONLY)
		if err != nil {
			log.Errorf("unable to open destination file: %v", err)
			return true, err
		}
		defer w.Close()
		n, err := io.Copy(w, r)
		if err != nil {
			log.Errorf("unable to copy: %v", err)
			return true, err
		}
		context.SetOutput(ovResult, n)
		return true, nil

	case methodRENAME:
		log.Debugf("method=%v source=%s destination=%s", methodRENAME,source, destination)
		err := c.Rename(source,destination)
		if err != nil {
			log.Errorf("unable to rename file: %v", err)
			return true, err
		}
		context.SetOutput(ovResult, "SUCCESS")
		return true, nil

	case methodDELETE:
		log.Debugf("method=%v source=%s", methodDELETE,source)
		err := c.Remove(source)
		if err != nil {
			log.Errorf("unable to rename file: %v", err)
			return true, err
		}
		context.SetOutput(ovResult, "SUCCESS")
		return true, nil
	default:
		return true, nil
	}
	return true, nil
}
