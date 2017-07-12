package cloudstack

import (
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"strings"

	"github.com/docker/machine/libmachine/drivers"
	"github.com/docker/machine/libmachine/log"
	"github.com/docker/machine/libmachine/mcnflag"
	"github.com/docker/machine/libmachine/ssh"
	"github.com/docker/machine/libmachine/state"
	"github.com/xanzy/go-cloudstack/cloudstack"
)

const (
	driverName = "cloudstack"
	dockerPort = 2376
	swarmPort  = 3376
)

type configError struct {
	option string
}

func (e *configError) Error() string {
	return fmt.Sprintf("cloudstack driver requires the --cloudstack-%s option", e.option)
}

type Driver struct {
	*drivers.BaseDriver
	Id                   string
	ApiURL               string
	ApiKey               string
	SecretKey            string
	HTTPGETOnly          bool
	JobTimeOut           int64
	UsePrivateIP         bool
	UsePortForward       bool
	PublicIP             string
	PublicIPID           string
	DisassociatePublicIP bool
	SSHKeyPair           string
	PrivateIP            string
	CIDRList             []string
	FirewallRuleIds      []string
	Expunge              bool
	Template             string
	TemplateID           string
	ServiceOffering      string
	ServiceOfferingID    string
	Network              string
	NetworkID            string
	Zone                 string
	ZoneID               string
	NetworkType          string
	UserDataFile         string
	UserData             string
}

// GetCreateFlags registers the flags this driver adds to
// "docker hosts create"
func (d *Driver) GetCreateFlags() []mcnflag.Flag {
	return []mcnflag.Flag{
		mcnflag.StringFlag{
			Name:   "cloudstack-api-url",
			Usage:  "CloudStack API URL",
			EnvVar: "CLOUDSTACK_API_URL",
		},
		mcnflag.StringFlag{
			Name:   "cloudstack-api-key",
			Usage:  "CloudStack API key",
			EnvVar: "CLOUDSTACK_API_KEY",
		},
		mcnflag.StringFlag{
			Name:   "cloudstack-secret-key",
			Usage:  "CloudStack API secret key",
			EnvVar: "CLOUDSTACK_SECRET_KEY",
		},
		mcnflag.BoolFlag{
			Name:   "cloudstack-http-get-only",
			Usage:  "Only use HTTP GET to execute CloudStack API",
			EnvVar: "CLOUDSTACK_HTTP_GET_ONLY",
		},
		mcnflag.IntFlag{
			Name:   "cloudstack-timeout",
			Usage:  "time(seconds) allowed to complete async job",
			EnvVar: "CLOUDSTACK_TIMEOUT",
			Value:  300,
		},
		mcnflag.BoolFlag{
			Name:  "cloudstack-use-private-address",
			Usage: "Use a private IP to access the machine",
		},
		mcnflag.BoolFlag{
			Name:  "cloudstack-use-port-forward",
			Usage: "Use port forwarding rule to access the machine",
		},
		mcnflag.StringFlag{
			Name:  "cloudstack-public-ip",
			Usage: "CloudStack Public IP",
		},
		mcnflag.StringFlag{
			Name:  "cloudstack-ssh-user",
			Usage: "CloudStack SSH user",
			Value: "root",
		},
		mcnflag.StringSliceFlag{
			Name:  "cloudstack-cidr",
			Usage: "Source CIDR to give access to the machine. default 0.0.0.0/0",
		},
		mcnflag.BoolFlag{
			Name:  "cloudstack-expunge",
			Usage: "Whether or not to expunge the machine upon removal",
		},
		mcnflag.StringFlag{
			Name:  "cloudstack-template",
			Usage: "CloudStack template",
		},
		mcnflag.StringFlag{
			Name:  "cloudstack-service-offering",
			Usage: "CloudStack service offering",
		},
		mcnflag.StringFlag{
			Name:  "cloudstack-network",
			Usage: "CloudStack network",
		},
		mcnflag.StringFlag{
			Name:  "cloudstack-zone",
			Usage: "CloudStack zone",
		},
		mcnflag.StringFlag{
			Name:  "cloudstack-userdata-file",
			Usage: "CloudStack Userdata file",
		},
	}
}

func NewDriver(hostName, storePath string) drivers.Driver {

	driver := &Driver{
		BaseDriver: &drivers.BaseDriver{
			MachineName: hostName,
			StorePath:   storePath,
		},
		FirewallRuleIds: []string{},
	}
	return driver
}

// DriverName returns the name of the driver as it is registered
func (d *Driver) DriverName() string {
	return driverName
}

func (d *Driver) GetSSHHostname() (string, error) {
	return d.GetIP()
}

func (d *Driver) GetSSHUsername() string {
	if d.SSHUser == "" {
		d.SSHUser = "root"
	}
	return d.SSHUser
}

// SetConfigFromFlags configures the driver with the object that was returned
// by RegisterCreateFlags
func (d *Driver) SetConfigFromFlags(flags drivers.DriverOptions) error {
	d.ApiURL = flags.String("cloudstack-api-url")
	d.ApiKey = flags.String("cloudstack-api-key")
	d.SecretKey = flags.String("cloudstack-secret-key")
	d.UsePrivateIP = flags.Bool("cloudstack-use-private-address")
	d.UsePortForward = flags.Bool("cloudstack-use-port-forward")
	d.HTTPGETOnly = flags.Bool("cloudstack-http-get-only")
	d.JobTimeOut = int64(flags.Int("cloudstack-timeout"))
	d.SSHUser = flags.String("cloudstack-ssh-user")
	d.CIDRList = flags.StringSlice("cloudstack-cidr")
	d.Expunge = flags.Bool("cloudstack-expunge")

	if err := d.setZone(flags.String("cloudstack-zone")); err != nil {
		return err
	}
	if err := d.setTemplate(flags.String("cloudstack-template")); err != nil {
		return err
	}
	if err := d.setServiceOffering(flags.String("cloudstack-service-offering")); err != nil {
		return err
	}
	if err := d.setNetwork(flags.String("cloudstack-network")); err != nil {
		return err
	}
	if err := d.setPublicIP(flags.String("cloudstack-public-ip")); err != nil {
		return err
	}
	if err := d.setUserData(flags.String("cloudstack-userdata-file")); err != nil {
		return err
	}

	d.SwarmMaster = flags.Bool("swarm-master")
	d.SwarmDiscovery = flags.String("swarm-discovery")

	d.SSHKeyPair = d.MachineName

	if d.ApiURL == "" {
		return &configError{option: "api-url"}
	}

	if d.ApiKey == "" {
		return &configError{option: "api-key"}
	}

	if d.SecretKey == "" {
		return &configError{option: "secret-key"}
	}

	if d.Template == "" {
		return &configError{option: "template"}
	}

	if d.ServiceOffering == "" {
		return &configError{option: "service-offering"}
	}

	if d.Zone == "" {
		return &configError{option: "zone"}
	}

	if len(d.CIDRList) == 0 {
		d.CIDRList = []string{"0.0.0.0/0"}
	}

	d.DisassociatePublicIP = false

	return nil
}

// GetURL returns a Docker compatible host URL for connecting to this host
// e.g. tcp://1.2.3.4:2376
func (d *Driver) GetURL() (string, error) {
	ip, err := d.GetIP()
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("tcp://%s:%d", ip, dockerPort), nil
}

// GetIP returns the IP that this host is available at
func (d *Driver) GetIP() (string, error) {
	if d.UsePrivateIP {
		return d.PrivateIP, nil
	}
	return d.PublicIP, nil
}

// GetState returns the state that the host is in (running, stopped, etc)
func (d *Driver) GetState() (state.State, error) {
	cs := d.getClient()
	vm, count, err := cs.VirtualMachine.GetVirtualMachineByID(d.Id)
	if err != nil {
		return state.Error, err
	}

	if count == 0 {
		return state.None, fmt.Errorf("Machine does not exist, use create command to create it")
	}

	switch vm.State {
	case "Starting":
		return state.Starting, nil
	case "Running":
		return state.Running, nil
	case "Stopping":
		return state.Running, nil
	case "Stopped":
		return state.Stopped, nil
	case "Destroyed":
		return state.Stopped, nil
	case "Expunging":
		return state.Stopped, nil
	case "Migrating":
		return state.Paused, nil
	case "Error":
		return state.Error, nil
	case "Unknown":
		return state.Error, nil
	case "Shutdowned":
		return state.Stopped, nil
	}

	return state.None, nil
}

// PreCreate allows for pre-create operations to make sure a driver is ready for creation
func (d *Driver) PreCreateCheck() error {

	if err := d.checkKeyPair(); err != nil {
		return err
	}

	if err := d.checkInstance(); err != nil {
		return err
	}

	return nil
}

// Create a host using the driver's config
func (d *Driver) Create() error {
	cs := d.getClient()

	if err := d.createKeyPair(); err != nil {
		return err
	}

	p := cs.VirtualMachine.NewDeployVirtualMachineParams(
		d.ServiceOfferingID, d.TemplateID, d.ZoneID)
	p.SetName(d.MachineName)
	p.SetDisplayname(d.MachineName)
	p.SetKeypair(d.SSHKeyPair)

	if d.UserData != "" {
		p.SetUserdata(d.UserData)
	}

	if d.NetworkID != "" {
		p.SetNetworkids([]string{d.NetworkID})
	}

	if d.NetworkType == "Basic" {
		if err := d.createSecurityGroup(); err != nil {
			return err
		}
		p.SetSecuritygroupnames([]string{d.MachineName})
	}

	// Create the machine
	log.Info("Creating CloudStack instance...")
	vm, err := cs.VirtualMachine.DeployVirtualMachine(p)
	if err != nil {
		return err
	}

	d.Id = vm.Id

	d.PrivateIP = vm.Nic[0].Ipaddress
	if d.NetworkType == "Basic" {
		d.PublicIP = d.PrivateIP
	}

	if d.NetworkType == "Advanced" && !d.UsePrivateIP {
		if d.PublicIPID == "" {
			if err := d.associatePublicIP(); err != nil {
				return err
			}
		}

		if err := d.configureFirewallRules(); err != nil {
			return err
		}

		if d.UsePortForward {
			if err := d.configurePortForwardingRules(); err != nil {
				return err
			}
		} else {
			if err := d.enableStaticNat(); err != nil {
				return err
			}
		}
	}

	return nil
}

// Remove a host
func (d *Driver) Remove() error {
	cs := d.getClient()
	p := cs.VirtualMachine.NewDestroyVirtualMachineParams(d.Id)
	p.SetExpunge(d.Expunge)

	if err := d.deleteFirewallRules(); err != nil {
		return err
	}

	if err := d.disassociatePublicIP(); err != nil {
		return err
	}

	log.Info("Removing CloudStack instance...")
	if _, err := cs.VirtualMachine.DestroyVirtualMachine(p); err != nil {
		return err
	}
	if d.NetworkType == "Basic" {
		if err := d.deleteSecurityGroup(); err != nil {
			return err
		}
	}

	if err := d.deleteKeyPair(); err != nil {
		return err
	}

	return nil
}

// Start a host
func (d *Driver) Start() error {
	vmstate, err := d.GetState()
	if err != nil {
		return err
	}

	if vmstate == state.Running {
		log.Info("Machine is already running")
		return nil
	}

	if vmstate == state.Starting {
		log.Info("Machine is already starting")
		return nil
	}

	cs := d.getClient()
	p := cs.VirtualMachine.NewStartVirtualMachineParams(d.Id)

	if _, err = cs.VirtualMachine.StartVirtualMachine(p); err != nil {
		return err
	}

	return nil
}

// Stop a host gracefully
func (d *Driver) Stop() error {
	vmstate, err := d.GetState()
	if err != nil {
		return err
	}

	if vmstate == state.Stopped {
		log.Info("Machine is already stopped")
		return nil
	}

	cs := d.getClient()
	p := cs.VirtualMachine.NewStopVirtualMachineParams(d.Id)

	if _, err = cs.VirtualMachine.StopVirtualMachine(p); err != nil {
		return err
	}

	return nil
}

// Restart a host.
func (d *Driver) Restart() error {
	vmstate, err := d.GetState()
	if err != nil {
		return err
	}

	if vmstate == state.Stopped {
		return fmt.Errorf("Machine is stopped, use start command to start it")
	}

	cs := d.getClient()
	p := cs.VirtualMachine.NewRebootVirtualMachineParams(d.Id)

	if _, err = cs.VirtualMachine.RebootVirtualMachine(p); err != nil {
		return err
	}

	return nil
}

// Kill stops a host forcefully
func (d *Driver) Kill() error {
	return d.Stop()
}

func (d *Driver) getClient() *cloudstack.CloudStackClient {
	cs := cloudstack.NewAsyncClient(d.ApiURL, d.ApiKey, d.SecretKey, false)
	cs.HTTPGETOnly = d.HTTPGETOnly
	cs.AsyncTimeout(d.JobTimeOut)
	return cs
}

func (d *Driver) setZone(zone string) error {
	d.Zone = zone
	d.ZoneID = ""
	d.NetworkType = ""

	if d.Zone == "" {
		return nil
	}

	cs := d.getClient()
	z, _, err := cs.Zone.GetZoneByName(d.Zone)
	if err != nil {
		return fmt.Errorf("Unable to get zone: %v", err)
	}

	d.ZoneID = z.Id
	d.NetworkType = z.Networktype

	log.Debugf("zone: %q", d.Zone)
	log.Debugf("zone id: %q", d.ZoneID)
	log.Debugf("network type: %q", d.NetworkType)

	return nil
}

func (d *Driver) setTemplate(template string) error {
	d.Template = template
	d.TemplateID = ""

	if d.Template == "" {
		return nil
	}

	if d.ZoneID == "" {
		return fmt.Errorf("Unable to get template id: zone is not set")
	}

	cs := d.getClient()
	templateid, counts, err := cs.Template.GetTemplateID(d.Template, "executable", d.ZoneID)
	if err != nil {
		return fmt.Errorf("Unable to get template id: %v", err)
	}

	if counts > 1 {
		return fmt.Errorf("Unable to specify template id")
	}

	d.TemplateID = templateid
	log.Debugf("template id: %q", d.TemplateID)

	return nil
}

func (d *Driver) setServiceOffering(serviceoffering string) error {
	d.ServiceOffering = serviceoffering
	d.ServiceOfferingID = ""

	if d.ServiceOffering == "" {
		return nil
	}

	cs := d.getClient()
	serviceofferingid, counts, err := cs.ServiceOffering.GetServiceOfferingID(d.ServiceOffering)
	if err != nil {
		return fmt.Errorf("Unable to get service offering id: %v", err)
	}

	if counts > 1 {
		return fmt.Errorf("Unable to specify service offering id")
	}

	d.ServiceOfferingID = serviceofferingid

	log.Debugf("service offering id: %q", d.ServiceOfferingID)

	return nil
}

func (d *Driver) setNetwork(network string) error {
	d.Network = network
	d.NetworkID = ""

	if d.Network == "" {
		return nil
	}

	cs := d.getClient()
	networkid, counts, err := cs.Network.GetNetworkID(d.Network)
	if err != nil {
		return fmt.Errorf("Unable to get network id: %v", err)
	}

	if counts > 1 {
		return fmt.Errorf("Unable to specify network id")
	}

	d.NetworkID = networkid

	log.Debugf("network id: %q", d.NetworkID)

	return nil
}

func (d *Driver) setPublicIP(publicip string) error {
	d.PublicIP = publicip
	d.PublicIPID = ""

	if d.PublicIP == "" {
		return nil
	}

	cs := d.getClient()
	p := cs.Address.NewListPublicIpAddressesParams()
	p.SetIpaddress(d.PublicIP)
	ips, err := cs.Address.ListPublicIpAddresses(p)
	if err != nil {
		return fmt.Errorf("Unable to get public ip id: %s", err)
	}
	if ips.Count < 1 {
		return fmt.Errorf("Unable to get public ip id: Not Found %s", d.PublicIP)
	}

	d.PublicIPID = ips.PublicIpAddresses[0].Id

	log.Debugf("public ip id: %q", d.PublicIPID)

	return nil
}

func (d *Driver) setUserData(userDataFile string) error {
	d.UserDataFile = userDataFile

	if d.UserDataFile == "" {
		return nil
	}

	data, err := ioutil.ReadFile(d.UserDataFile)
	if err != nil {
		return fmt.Errorf("Failed to read user data file: %s", err)
	}

	d.UserData = base64.StdEncoding.EncodeToString(data)

	return nil
}

func (d *Driver) checkKeyPair() error {
	cs := d.getClient()

	log.Infof("Checking if SSH key pair (%v) already exists...", d.SSHKeyPair)

	p := cs.SSH.NewListSSHKeyPairsParams()
	p.SetName(d.SSHKeyPair)
	res, err := cs.SSH.ListSSHKeyPairs(p)
	if err != nil {
		return err
	}
	if res.Count > 0 {
		return fmt.Errorf("SSH key pair (%v) already exists.", d.SSHKeyPair)
	}
	return nil
}

func (d *Driver) checkInstance() error {
	cs := d.getClient()

	log.Infof("Checking if instance (%v) already exists...", d.MachineName)

	p := cs.VirtualMachine.NewListVirtualMachinesParams()
	p.SetName(d.MachineName)
	p.SetZoneid(d.ZoneID)
	res, err := cs.VirtualMachine.ListVirtualMachines(p)
	if err != nil {
		return err
	}
	if res.Count > 0 {
		return fmt.Errorf("Instance (%v) already exists.", d.SSHKeyPair)
	}
	return nil
}

func (d *Driver) createKeyPair() error {
	cs := d.getClient()

	if err := ssh.GenerateSSHKey(d.GetSSHKeyPath()); err != nil {
		return err
	}

	publicKey, err := ioutil.ReadFile(d.GetSSHKeyPath() + ".pub")
	if err != nil {
		return err
	}

	log.Infof("Registering SSH key pair...")

	p := cs.SSH.NewRegisterSSHKeyPairParams(d.SSHKeyPair, string(publicKey))
	if _, err := cs.SSH.RegisterSSHKeyPair(p); err != nil {
		return err
	}

	return nil
}

func (d *Driver) deleteKeyPair() error {
	cs := d.getClient()

	log.Infof("Deleting SSH key pair...")

	p := cs.SSH.NewDeleteSSHKeyPairParams(d.SSHKeyPair)
	if _, err := cs.SSH.DeleteSSHKeyPair(p); err != nil {
		return err
	}
	return nil
}

func (d *Driver) associatePublicIP() error {
	cs := d.getClient()
	log.Infof("Associating public ip address...")
	p := cs.Address.NewAssociateIpAddressParams()
	p.SetZoneid(d.ZoneID)
	if d.NetworkID != "" {
		p.SetNetworkid(d.NetworkID)
	}
	ip, err := cs.Address.AssociateIpAddress(p)
	if err != nil {
		return err
	}
	d.PublicIP = ip.Ipaddress
	d.PublicIPID = ip.Id
	d.DisassociatePublicIP = true

	return nil
}

func (d *Driver) disassociatePublicIP() error {
	if !d.DisassociatePublicIP {
		return nil
	}

	cs := d.getClient()
	log.Infof("Disassociating public ip address...")
	p := cs.Address.NewDisassociateIpAddressParams(d.PublicIPID)
	if _, err := cs.Address.DisassociateIpAddress(p); err != nil {
		return err
	}

	return nil
}

func (d *Driver) enableStaticNat() error {
	cs := d.getClient()
	log.Infof("Enabling Static Nat...")
	p := cs.NAT.NewEnableStaticNatParams(d.PublicIPID, d.Id)
	if _, err := cs.NAT.EnableStaticNat(p); err != nil {
		return err
	}

	return nil
}

func (d *Driver) configureFirewallRule(publicPort, privatePort int) error {
	cs := d.getClient()

	log.Debugf("Creating firewall rule ... : cidr list: %v, port %d", d.CIDRList, publicPort)
	p := cs.Firewall.NewCreateFirewallRuleParams(d.PublicIPID, "tcp")
	p.SetCidrlist(d.CIDRList)
	p.SetStartport(publicPort)
	p.SetEndport(publicPort)
	rule, err := cs.Firewall.CreateFirewallRule(p)
	if err != nil {
		// If the error reports the port is already open, just ignore.
		if !strings.Contains(err.Error(), fmt.Sprintf(
			"The range specified, %d-%d, conflicts with rule", publicPort, publicPort)) {
			return err
		}
	} else {
		d.FirewallRuleIds = append(d.FirewallRuleIds, rule.Id)
	}

	return nil
}

func (d *Driver) configurePortForwardingRule(publicPort, privatePort int) error {
	cs := d.getClient()

	log.Debugf("Creating port forwarding rule ... : cidr list: %v, port %d", d.CIDRList, publicPort)
	p := cs.Firewall.NewCreatePortForwardingRuleParams(
		d.PublicIPID, privatePort, "tcp", publicPort, d.Id)
	p.SetOpenfirewall(false)
	if _, err := cs.Firewall.CreatePortForwardingRule(p); err != nil {
		return err
	}

	return nil
}

func (d *Driver) configureFirewallRules() error {
	log.Info("Creating firewall rule for ssh port ...")

	if err := d.configureFirewallRule(22, 22); err != nil {
		return err
	}

	log.Info("Creating firewall rule for docker port ...")
	if err := d.configureFirewallRule(dockerPort, dockerPort); err != nil {
		return err
	}

	if d.SwarmMaster {
		log.Info("Creating firewall rule for swarm port ...")
		if err := d.configureFirewallRule(swarmPort, swarmPort); err != nil {
			return err
		}
	}

	return nil
}

func (d *Driver) deleteFirewallRules() error {
	if len(d.FirewallRuleIds) > 0 {
		log.Info("Removing firewall rules...")
		for _, id := range d.FirewallRuleIds {
			cs := d.getClient()
			f := cs.Firewall.NewDeleteFirewallRuleParams(id)
			if _, err := cs.Firewall.DeleteFirewallRule(f); err != nil {
				return err
			}
		}
	}
	return nil
}

func (d *Driver) configurePortForwardingRules() error {
	log.Info("Creating port forwarding rule for ssh port ...")

	if err := d.configurePortForwardingRule(22, 22); err != nil {
		return err
	}

	log.Info("Creating port forwarding rule for docker port ...")
	if err := d.configurePortForwardingRule(dockerPort, dockerPort); err != nil {
		return err
	}

	if d.SwarmMaster {
		log.Info("Creating port forwarding rule for swarm port ...")
		if err := d.configurePortForwardingRule(swarmPort, swarmPort); err != nil {
			return err
		}
	}

	return nil
}

func (d *Driver) createSecurityGroup() error {
	log.Debugf("Creating security group ...")
	cs := d.getClient()

	p1 := cs.SecurityGroup.NewCreateSecurityGroupParams(d.MachineName)
	if _, err := cs.SecurityGroup.CreateSecurityGroup(p1); err != nil {
		return err
	}

	p2 := cs.SecurityGroup.NewAuthorizeSecurityGroupIngressParams()
	p2.SetSecuritygroupname(d.MachineName)
	p2.SetProtocol("tcp")
	p2.SetCidrlist(d.CIDRList)

	p2.SetStartport(22)
	p2.SetEndport(22)
	if _, err := cs.SecurityGroup.AuthorizeSecurityGroupIngress(p2); err != nil {
		return err
	}

	p2.SetStartport(dockerPort)
	p2.SetEndport(dockerPort)
	if _, err := cs.SecurityGroup.AuthorizeSecurityGroupIngress(p2); err != nil {
		return err
	}

	if d.SwarmMaster {
		p2.SetStartport(swarmPort)
		p2.SetEndport(swarmPort)
		if _, err := cs.SecurityGroup.AuthorizeSecurityGroupIngress(p2); err != nil {
			return err
		}
	}
	return nil
}

func (d *Driver) deleteSecurityGroup() error {
	log.Debugf("Deleting security group ...")
	cs := d.getClient()

	p := cs.SecurityGroup.NewDeleteSecurityGroupParams()
	p.SetName(d.MachineName)
	if _, err := cs.SecurityGroup.DeleteSecurityGroup(p); err != nil {
		return err
	}
	return nil
}
