package sftp

import (
	"io/ioutil"
	"testing"

	"github.com/TIBCOSoftware/flogo-lib/core/activity"
	"github.com/TIBCOSoftware/flogo-contrib/action/flow/test"
	"os"
)

var activityMetadata *activity.Metadata

func getActivityMetadata() *activity.Metadata {

	if activityMetadata == nil {
		jsonMetadataBytes, err := ioutil.ReadFile("activity.json")
		if err != nil{
			panic("No Json Metadata found for activity.json path")
		}

		activityMetadata = activity.NewMetadata(string(jsonMetadataBytes))
	}

	return activityMetadata
}

func TestCreate(t *testing.T) {

	act := NewActivity(getActivityMetadata())

	if act == nil {
		t.Error("Activity Not Created")
		t.Fail()
		return
	}
}

func TestEvalGETLinuxToWindows(t *testing.T) {

	defer func() {
		if r := recover(); r != nil {
			t.Failed()
			t.Errorf("panic during execution: %v", r)
		}
	}()

	act := NewActivity(getActivityMetadata())
	tc := test.NewTestActivityContext(getActivityMetadata())
	tc.SetInput("host","192.168.11.3")
	tc.SetInput("port",22)
	tc.SetInput("user","tibadm")
	tc.SetInput("password",os.Getenv("TIBADM_PASSWORD"))
	tc.SetInput("method","GET")
	tc.SetInput("source","/tmp/sftptest/server/test-server.txt")
	tc.SetInput("destination","D:/Temp/test-server.txt")
	//setup attrs

	act.Eval(tc)

	//check result attr
}

func TestEvalPUTWindowsToLinux(t *testing.T) {

	defer func() {
		if r := recover(); r != nil {
			t.Failed()
			t.Errorf("panic during execution: %v", r)
		}
	}()

	act := NewActivity(getActivityMetadata())
	tc := test.NewTestActivityContext(getActivityMetadata())
	tc.SetInput("host","192.168.11.3")
	tc.SetInput("port",22)
	tc.SetInput("user","tibadm")
	tc.SetInput("password",os.Getenv("TIBADM_PASSWORD"))
	tc.SetInput("method","PUT")
	tc.SetInput("source","D:/Temp/test-local.txt")
	tc.SetInput("destination","/tmp/sftptest/server/test-local.txt")
	//setup attrs

	act.Eval(tc)

	//check result attr
}