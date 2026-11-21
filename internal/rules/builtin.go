package rules

import (
	"fmt"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/example/cluster-admission-guard/internal/policy"
	"github.com/example/cluster-admission-guard/internal/workload"
)

// --- pod.privileged ---------------------------------------------------------------

type privilegedRule struct{}

func (privilegedRule) ID() string { return policy.RulePrivileged }

func (r privilegedRule) Evaluate(_ *Context, spec *workload.PodSpec, _ map[string]any, mutate bool) Result {
	var res Result
	for _, c := range spec.Containers {
		sc := containerContext(c)
		priv, set := workload.GetBool(sc, "privileged")
		if !set || !priv {
			continue
		}
		if mutate {
			workload.SetBool(sc, "privileged", false)
			// Privileged mode implies these capabilities; leaving them behind
			// would keep the container effectively privileged-looking to other
			// tooling and to a later re-enable of privileged mode.
			stripPrivilegedCaps(c)
			res.Findings = append(res.Findings, remediated(
				r.ID(), "critical", c.Path+".securityContext.privileged", c.Name,
				fmt.Sprintf("container %q runs in privileged mode", c.Name),
				"set securityContext.privileged to false"))
			res.Remediated++
			continue
		}
		res.Findings = append(res.Findings, deny(
			r.ID(), "critical", c.Path+".securityContext.privileged", c.Name,
			fmt.Sprintf("container %q runs in privileged mode; this grants all Linux capabilities and full device access", c.Name)))
	}
	return res
}

// stripPrivilegedCaps removes the capabilities that only make sense with
// privileged mode.
func stripPrivilegedCaps(c *workload.Container) {
	sc := containerContext(c)
	if sc == nil {
		return
	}
	caps := workload.GetMap(sc, "capabilities")
	if allow, ok := workload.GetStringSlice(caps, "add"); ok {
		var kept []string
		for _, cap := range allow {
			switch strings.ToUpper(cap) {
			case "SYS_ADMIN", "SYS_PTRACE", "SYS_MODULE", "SYS_RAWIO",
				"DAC_READ_SEARCH", "NET_ADMIN", "SYS_BOOT", "SYS_TIME", "BPF":
				continue
			}
			kept = append(kept, cap)
		}
		if len(kept) != len(allow) {
			if len(kept) == 0 {
				workload.RemoveKey(caps, "add")
			} else {
				workload.SetStringSlice(caps, "add", kept)
			}
		}
	}
	// hostPath-backed volumes are handled by the hostPath rule; a privileged
	// container also implicitly ignores seccomp, which is covered by
	// pod.seccompProfile when it inspects the effective profile.
}

// --- pod.allowPrivilegeEscalation -------------------------------------------------

type allowPrivilegeEscalationRule struct{}

func (allowPrivilegeEscalationRule) ID() string { return policy.RulePrivilegeEscalation }

func (r allowPrivilegeEscalationRule) Evaluate(_ *Context, spec *workload.PodSpec, _ map[string]any, mutate bool) Result {
	var res Result
	for _, c := range spec.Containers {
		sc := containerContext(c)
		if apt, set := workload.GetBool(sc, "allowPrivilegeEscalation"); set && !apt {
			continue
		}
		// Kubernetes defaults allowPrivilegeEscalation to true when it is
		// omitted, so an absent value is as dangerous as an explicit true.
		wasSet := false
		if sc != nil {
			_, wasSet = workload.GetBool(sc, "allowPrivilegeEscalation")
		}
		if mutate {
			workload.SetBool(workload.EnsureMap(c.Obj, "securityContext"), "allowPrivilegeEscalation", false)
			res.Findings = append(res.Findings, remediated(
				r.ID(), "high", c.Path+".securityContext.allowPrivilegeEscalation", c.Name,
				fmt.Sprintf("container %q allows privilege escalation", c.Name),
				"set securityContext.allowPrivilegeEscalation to false"))
			res.Remediated++
			continue
		}
		detail := "is unset (Kubernetes defaults it to true)"
		if wasSet {
			detail = "is true"
		}
		res.Findings = append(res.Findings, deny(
			r.ID(), "high", c.Path+".securityContext.allowPrivilegeEscalation", c.Name,
			fmt.Sprintf("container %q allowPrivilegeEscalation %s; setuid/file-capability binaries could gain privileges", c.Name, detail)))
	}
	return res
}

// --- pod.capabilities -------------------------------------------------------------

type capabilitiesRule struct{}

func (capabilitiesRule) ID() string { return policy.RuleCapabilities }

var dangerousCaps = map[string]bool{
	"SYS_ADMIN": true, "SYS_PTRACE": true, "SYS_MODULE": true, "SYS_RAWIO": true,
	"DAC_READ_SEARCH": true, "NET_ADMIN": true, "SYS_BOOT": true, "SYS_TIME": true,
	"BPF": true, "PERFMON": true, "MAC_ADMIN": true, "MAC_OVERRIDE": true,
	"SYSLOG": true, "NET_RAW": true, "CHECKPOINT_RESTORE": true,
}

func (r capabilitiesRule) Evaluate(_ *Context, spec *workload.PodSpec, cfg map[string]any, mutate bool) Result {
	allowed := cfgStrings(cfg, "allowed")
	var res Result
	for _, c := range spec.Containers {
		sc := containerContext(c)
		caps := workload.GetMap(sc, "capabilities")
		added, _ := workload.GetStringSlice(caps, "add")
		dropped, _ := workload.GetStringSlice(caps, "drop")
		dropsAll := containsFold(dropped, "ALL")

		var offending []string
		for _, cap := range added {
			up := strings.ToUpper(strings.TrimPrefix(strings.ToUpper(cap), "CAP_"))
			if dropsAll {
				offending = append(offending, cap)
				continue
			}
			if len(allowed) > 0 {
				if !containsFold(allowed, up) {
					offending = append(offending, cap)
				}
				continue
			}
			if dangerousCaps[up] {
				offending = append(offending, cap)
			}
		}
		if len(offending) == 0 {
			continue
		}
		if mutate {
			kept := added[:0:0]
			for _, cap := range added {
				keep := true
				for _, bad := range offending {
					if cap == bad {
						keep = false
					}
				}
				if keep {
					kept = append(kept, cap)
				}
			}
			if len(kept) == 0 {
				workload.RemoveKey(caps, "add")
			} else {
				workload.SetStringSlice(caps, "add", kept)
			}
			res.Findings = append(res.Findings, remediated(
				r.ID(), "high", c.Path+".securityContext.capabilities.add", c.Name,
				fmt.Sprintf("container %q adds dangerous capabilities: %s", c.Name, fmtList(offending)),
				"remove "+fmtList(offending)+" from securityContext.capabilities.add"))
			res.Remediated++
			continue
		}
		res.Findings = append(res.Findings, deny(
			r.ID(), "high", c.Path+".securityContext.capabilities.add", c.Name,
			fmt.Sprintf("container %q adds dangerous capabilities: %s", c.Name, fmtList(offending))))
	}
	return res
}

func containsFold(list []string, want string) bool {
	for _, item := range list {
		if strings.EqualFold(strings.TrimPrefix(strings.ToUpper(item), "CAP_"), want) {
			return true
		}
	}
	return false
}

// --- pod.seccompProfile -----------------------------------------------------------

type seccompRule struct{}

func (seccompRule) ID() string { return policy.RuleSeccompProfile }

func (r seccompRule) Evaluate(_ *Context, spec *workload.PodSpec, _ map[string]any, mutate bool) Result {
	podSC := podContext(spec)
	podType := ""
	if prof := workload.GetMap(podSC, "seccompProfile"); prof != nil {
		podType, _ = workload.GetString(prof, "type")
	}
	// Unconfined at pod level affects every container that does not override it.
	podUnconfined := podType == "Unconfined"

	var res Result
	for _, c := range spec.Containers {
		sc := containerContext(c)
		typ := ""
		set := false
		if prof := workload.GetMap(sc, "seccompProfile"); prof != nil {
			typ, set = workload.GetString(prof, "type")
		}
		if !set && !podUnconfined {
			// Pod-level RuntimeDefault or Localhost applies to this container.
			continue
		}
		if set && typ != "Unconfined" {
			continue
		}
		if mutate {
			prof := workload.EnsureMap(workload.EnsureMap(c.Obj, "securityContext"), "seccompProfile")
			prof["type"] = "RuntimeDefault"
			workload.RemoveKey(prof, "localhostProfile")
			res.Findings = append(res.Findings, remediated(
				r.ID(), "high", c.Path+".securityContext.seccompProfile.type", c.Name,
				fmt.Sprintf("container %q disables seccomp", c.Name),
				"set securityContext.seccompProfile.type to RuntimeDefault"))
			res.Remediated++
			continue
		}
		res.Findings = append(res.Findings, deny(
			r.ID(), "high", c.Path+".securityContext.seccompProfile.type", c.Name,
			fmt.Sprintf("container %q runs with seccomp Unconfined (or a pod-level Unconfined profile)", c.Name)))
	}
	return res
}

// --- pod.runAsNonRoot -------------------------------------------------------------

type runAsNonRootRule struct{}

func (runAsNonRootRule) ID() string { return policy.RuleRunAsNonRoot }

func (r runAsNonRootRule) Evaluate(_ *Context, spec *workload.PodSpec, _ map[string]any, mutate bool) Result {
	var res Result
	for _, c := range spec.Containers {
		if v, set := lookupBool(c, spec, "runAsNonRoot"); set && v {
			continue
		}
		// A numeric non-zero UID is acceptable even without runAsNonRoot: the
		// kubelet will run as that user regardless.
		uid, hasUID := lookupRunAsUser(c, spec)
		if !hasUID || uid == 0 {
			if mutate {
				workload.SetBool(workload.EnsureMap(c.Obj, "securityContext"), "runAsNonRoot", true)
				res.Findings = append(res.Findings, remediated(
					r.ID(), "high", c.Path+".securityContext.runAsNonRoot", c.Name,
					fmt.Sprintf("container %q may run as root", c.Name),
					"set securityContext.runAsNonRoot to true"))
				res.Remediated++
				continue
			}
			res.Findings = append(res.Findings, deny(
				r.ID(), "high", c.Path+".securityContext.runAsNonRoot", c.Name,
				fmt.Sprintf("container %q does not set runAsNonRoot and may run as root", c.Name)))
			continue
		}
	}
	return res
}

func lookupRunAsUser(c *workload.Container, spec *workload.PodSpec) (int64, bool) {
	if v, ok := workload.GetInt64(containerContext(c), "runAsUser"); ok {
		return v, true
	}
	if v, ok := workload.GetInt64(podContext(spec), "runAsUser"); ok {
		return v, true
	}
	return 0, false
}

// --- pod.readOnlyRootFilesystem ----------------------------------------------------

type readOnlyRootFSRule struct{}

func (readOnlyRootFSRule) ID() string { return policy.RuleReadOnlyRootFilesystem }

func (r readOnlyRootFSRule) Evaluate(_ *Context, spec *workload.PodSpec, _ map[string]any, mutate bool) Result {
	var res Result
	for _, c := range spec.Containers {
		v, set := workload.GetBool(containerContext(c), "readOnlyRootFilesystem")
		if set && v {
			continue
		}
		if mutate {
			workload.SetBool(workload.EnsureMap(c.Obj, "securityContext"), "readOnlyRootFilesystem", true)
			res.Findings = append(res.Findings, remediated(
				r.ID(), "medium", c.Path+".securityContext.readOnlyRootFilesystem", c.Name,
				fmt.Sprintf("container %q has a writable root filesystem", c.Name),
				"set securityContext.readOnlyRootFilesystem to true"))
			res.Remediated++
			continue
		}
		res.Findings = append(res.Findings, deny(
			r.ID(), "medium", c.Path+".securityContext.readOnlyRootFilesystem", c.Name,
			fmt.Sprintf("container %q has a writable root filesystem", c.Name)))
	}
	return res
}

// --- pod.hostPathVolumes -----------------------------------------------------------

type hostPathRule struct{}

func (hostPathRule) ID() string { return policy.RuleHostPath }

func (r hostPathRule) Evaluate(_ *Context, spec *workload.PodSpec, cfg map[string]any, mutate bool) Result {
	allowedPrefixes := cfgStrings(cfg, "allowedPaths")
	var res Result
	for _, vol := range spec.Volumes() {
		hp := workload.GetMap(vol, "hostPath")
		if hp == nil {
			continue
		}
		p, _ := workload.GetString(hp, "path")
		name, _ := workload.GetString(vol, "name")
		if len(allowedPrefixes) > 0 && allowedPathPrefix(allowedPrefixes, p) {
			continue
		}
		res.Findings = append(res.Findings, deny(
			r.ID(), "critical", spec.FieldPath("volumes", name, "hostPath", "path"), name,
			fmt.Sprintf("volume %q mounts host path %q; this exposes the node filesystem to the container", name, p)))
	}
	return res
}

func allowedPathPrefix(prefixes []string, p string) bool {
	// Reject traversal up front: "/var/log/pods/../../etc" cleans to a path that
	// is outside the allowed prefix, but a naive prefix check on the cleaned
	// value can still be fooled by symlinks the kubelet would follow.
	if hasDotDot(p) {
		return false
	}
	if !path.IsAbs(p) {
		return false
	}
	cleaned := path.Clean(p)
	for _, prefix := range prefixes {
		base := path.Clean(prefix)
		if base == "/" {
			return true
		}
		if cleaned == base || strings.HasPrefix(cleaned, base+"/") {
			return true
		}
	}
	return false
}

func hasDotDot(p string) bool {
	for _, seg := range strings.Split(p, "/") {
		if seg == ".." {
			return true
		}
	}
	return false
}

// --- pod.hostNamespaces ------------------------------------------------------------

type hostNamespaceRule struct{}

func (hostNamespaceRule) ID() string { return policy.RuleHostNamespaces }

func (r hostNamespaceRule) Evaluate(_ *Context, spec *workload.PodSpec, _ map[string]any, mutate bool) Result {
	var res Result
	for _, field := range []string{"hostNetwork", "hostPID", "hostIPC"} {
		v, ok := workload.GetBool(spec.Obj, field)
		if !ok || !v {
			continue
		}
		if mutate {
			workload.SetBool(spec.Obj, field, false)
			res.Findings = append(res.Findings, remediated(
				r.ID(), "critical", spec.FieldPath(field), "",
				fmt.Sprintf("pod uses the host %s namespace", strings.TrimPrefix(field, "host")),
				"set "+field+" to false"))
			res.Remediated++
			continue
		}
		res.Findings = append(res.Findings, deny(
			r.ID(), "critical", spec.FieldPath(field), "",
			fmt.Sprintf("pod uses the host %s namespace; it can observe or manipulate other processes on the node", strings.TrimPrefix(field, "host"))))
	}
	return res
}

// --- pod.hostUsers ----------------------------------------------------------------

type hostUsersRule struct{}

func (hostUsersRule) ID() string { return policy.RuleHostUsers }

func (r hostUsersRule) Evaluate(_ *Context, spec *workload.PodSpec, _ map[string]any, mutate bool) Result {
	v, ok := workload.GetBool(spec.Obj, "hostUsers")
	if !ok || !v {
		return Result{}
	}
	if mutate {
		workload.SetBool(spec.Obj, "hostUsers", false)
		return Result{
			Findings: []policy.Finding{remediated(
				r.ID(), "high", spec.FieldPath("hostUsers"), "",
				"pod shares the host user namespace", "set hostUsers to false")},
			Remediated: 1,
		}
	}
	return Result{Findings: []policy.Finding{deny(
		r.ID(), "high", spec.FieldPath("hostUsers"), "",
		"pod shares the host user namespace, so UIDs inside the pod map to host UIDs")}}
}

// --- pod.hostPorts ----------------------------------------------------------------

type hostPortRule struct{}

func (hostPortRule) ID() string { return policy.RuleHostPorts }

func (r hostPortRule) Evaluate(_ *Context, spec *workload.PodSpec, cfg map[string]any, mutate bool) Result {
	allowed := cfgInts(cfg, "allowedPorts")
	var res Result
	for _, c := range spec.Containers {
		ports, ok := c.Obj["ports"].([]any)
		if !ok {
			continue
		}
		for i, raw := range ports {
			pm, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			hostPort, ok := workload.GetInt64(pm, "hostPort")
			if !ok || hostPort == 0 {
				continue
			}
			if len(allowed) > 0 && int64Contains(allowed, hostPort) {
				continue
			}
			p := fmt.Sprintf("%s.ports[%d].hostPort", c.Path, i)
			if mutate {
				workload.RemoveKey(pm, "hostPort")
				res.Findings = append(res.Findings, remediated(
					r.ID(), "high", p, c.Name,
					fmt.Sprintf("container %q binds host port %d", c.Name, hostPort),
					"remove hostPort from the container port"))
				res.Remediated++
				continue
			}
			res.Findings = append(res.Findings, deny(
				r.ID(), "high", p, c.Name,
				fmt.Sprintf("container %q binds host port %d; the pod can intercept node traffic", c.Name, hostPort)))
		}
	}
	return res
}

func int64Contains(list []int64, v int64) bool {
	for _, n := range list {
		if n == v {
			return true
		}
	}
	return false
}

// --- pod.volumeTypes ---------------------------------------------------------------

type volumeTypesRule struct{}

func (volumeTypesRule) ID() string { return policy.RuleVolumeTypes }

// highRiskVolumes are volume source types that give broad host access. The map
// value is a short explanation used in the denial message.
var highRiskVolumes = map[string]string{
	"hostPath":             "arbitrary host filesystem access",
	"nfs":                  "network filesystem that can expose other workloads' data",
	"iscsi":                "iSCSI LUN access",
	"rbd":                  "Ceph RBD block device access",
	"cephfs":               "CephFS mount",
	"cinder":               "block device attachment",
	"fc":                   "fibre channel LUN access",
	"flexVolume":           "out-of-tree driver with no admission review",
	"csi":                  "third-party CSI driver; review the driver",
	"glusterfs":            "GlusterFS mount",
	"portworxVolume":       "Portworx volume",
	"vsphereVolume":        "vSphere volume",
	"azureDisk":            "Azure disk attachment",
	"gcePersistentDisk":    "GCE disk attachment",
	"awsElasticBlockStore": "AWS EBS attachment",
	"projected":            "projected service-account or secret data",
}

func (r volumeTypesRule) Evaluate(_ *Context, spec *workload.PodSpec, cfg map[string]any, mutate bool) Result {
	allowed := cfgStrings(cfg, "allowed")
	// Sort the volume kinds so findings (and therefore denial messages) are
	// deterministic regardless of Go map iteration order.
	kinds := make([]string, 0, len(highRiskVolumes))
	for kind := range highRiskVolumes {
		kinds = append(kinds, kind)
	}
	sort.Strings(kinds)

	var res Result
	for _, vol := range spec.Volumes() {
		name, _ := workload.GetString(vol, "name")
		for _, kind := range kinds {
			reason := highRiskVolumes[kind]
			if _, ok := vol[kind]; !ok {
				continue
			}
			if len(allowed) > 0 && contains(allowed, kind) {
				continue
			}
			if kind == "hostPath" {
				// hostPath has its own rule with configurable prefixes, so it is
				// not double-reported here.
				continue
			}
			res.Findings = append(res.Findings, deny(
				r.ID(), "high", spec.FieldPath("volumes", name, kind), name,
				fmt.Sprintf("volume %q uses %q: %s", name, kind, reason)))
		}
	}
	return res
}

// --- pod.unsafeSysctls -------------------------------------------------------------

type unsafeSysctlsRule struct{}

func (unsafeSysctlsRule) ID() string { return policy.RuleUnsafeSysctls }

// safeSysctls are namespaced sysctls the kubelet allows by default.
var safeSysctls = map[string]bool{
	"kernel.shm_rmid_forced":              true,
	"net.ipv4.ip_local_port_range":        true,
	"net.ipv4.tcp_syncookies":             true,
	"net.ipv4.ping_group_range":           true,
	"net.ipv4.ip_unprivileged_port_start": true,
	"net.ipv4.ip_local_reserved_ports":    true,
	"net.ipv4.tcp_keepalive_time":         true,
	"net.ipv4.tcp_fin_timeout":            true,
	"net.ipv4.tcp_keepalive_intvl":        true,
	"net.ipv4.tcp_keepalive_probes":       true,
}

func (r unsafeSysctlsRule) Evaluate(_ *Context, spec *workload.PodSpec, _ map[string]any, _ bool) Result {
	var res Result
	sc := podContext(spec)
	list, _ := sc["sysctls"].([]any)
	for i, raw := range list {
		item, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		name, _ := workload.GetString(item, "name")
		if name == "" || safeSysctls[name] {
			continue
		}
		res.Findings = append(res.Findings, deny(
			r.ID(), "high", spec.FieldPath("securityContext", "sysctls", fmt.Sprintf("%d", i)), "",
			fmt.Sprintf("pod sets unsafe sysctl %q", name)))
	}
	return res
}

// --- pod.ephemeralContainers -------------------------------------------------------

type ephemeralContainersRule struct{}

func (ephemeralContainersRule) ID() string { return policy.RuleEphemeralContainers }

// Evaluate flags ephemeral containers: they can be attached to a running pod
// (kubectl debug) and bypass the object review that happened at pod creation.
func (ephemeralContainersRule) Evaluate(_ *Context, spec *workload.PodSpec, _ map[string]any, _ bool) Result {
	var res Result
	for _, c := range spec.Containers {
		if c.Role != workload.RoleEphemeral {
			continue
		}
		res.Findings = append(res.Findings, deny(
			policy.RuleEphemeralContainers, "high", c.Path, c.Name,
			fmt.Sprintf("ephemeral container %q attached to the pod; debug containers bypass the pod's original security review", c.Name)))
	}
	return res
}

// --- pod.procMount ---------------------------------------------------------------

type procMountRule struct{}

func (procMountRule) ID() string { return policy.RuleProcMount }

func (r procMountRule) Evaluate(_ *Context, spec *workload.PodSpec, _ map[string]any, mutate bool) Result {
	var res Result
	for _, c := range spec.Containers {
		sc := containerContext(c)
		mode, ok := workload.GetString(sc, "procMount")
		if !ok || mode == "" || mode == "Default" {
			continue
		}
		if mutate {
			workload.RemoveKey(sc, "procMount")
			res.Findings = append(res.Findings, remediated(
				r.ID(), "high", c.Path+".securityContext.procMount", c.Name,
				fmt.Sprintf("container %q uses procMount %q", c.Name, mode),
				"remove securityContext.procMount"))
			res.Remediated++
			continue
		}
		res.Findings = append(res.Findings, deny(
			r.ID(), "high", c.Path+".securityContext.procMount", c.Name,
			fmt.Sprintf("container %q uses procMount %q, exposing a writable /proc", c.Name, mode)))
	}
	return res
}

// --- pod.hostProcess -------------------------------------------------------------

type hostProcessRule struct{}

func (hostProcessRule) ID() string { return policy.RuleHostProcess }

func (r hostProcessRule) Evaluate(_ *Context, spec *workload.PodSpec, _ map[string]any, mutate bool) Result {
	var res Result
	for _, c := range spec.Containers {
		windows := workload.GetMap(containerContext(c), "windowsOptions")
		if windows == nil {
			continue
		}
		hp, ok := workload.GetBool(windows, "hostProcess")
		if !ok || !hp {
			continue
		}
		if mutate {
			workload.SetBool(windows, "hostProcess", false)
			res.Findings = append(res.Findings, remediated(
				r.ID(), "critical", c.Path+".securityContext.windowsOptions.hostProcess", c.Name,
				fmt.Sprintf("Windows container %q runs as a host process", c.Name),
				"set securityContext.windowsOptions.hostProcess to false"))
			res.Remediated++
			continue
		}
		res.Findings = append(res.Findings, deny(
			r.ID(), "critical", c.Path+".securityContext.windowsOptions.hostProcess", c.Name,
			fmt.Sprintf("Windows container %q runs as a host process with node privileges", c.Name)))
	}
	return res
}

// --- pod.shareProcessNamespace -----------------------------------------------------

type shareProcessNamespaceRule struct{}

func (shareProcessNamespaceRule) ID() string { return policy.RuleShareProcessNamespace }

func (r shareProcessNamespaceRule) Evaluate(_ *Context, spec *workload.PodSpec, _ map[string]any, mutate bool) Result {
	v, ok := workload.GetBool(spec.Obj, "shareProcessNamespace")
	if !ok || !v {
		return Result{}
	}
	if mutate {
		workload.SetBool(spec.Obj, "shareProcessNamespace", false)
		return Result{
			Findings: []policy.Finding{remediated(
				r.ID(), "medium", spec.FieldPath("shareProcessNamespace"), "",
				"pod shares its process namespace between containers",
				"set shareProcessNamespace to false")},
			Remediated: 1,
		}
	}
	return Result{Findings: []policy.Finding{deny(
		r.ID(), "medium", spec.FieldPath("shareProcessNamespace"), "",
		"pod shares its process namespace between containers, allowing one container to signal or inspect another")}}
}

// --- image rules -------------------------------------------------------------------

type imageProvenanceRule struct{}

func (imageProvenanceRule) ID() string { return policy.RuleImageProvenance }

func (r imageProvenanceRule) Evaluate(ctx *Context, spec *workload.PodSpec, cfg map[string]any, _ bool) Result {
	allowedRegistries := cfgStrings(cfg, "allowedRegistries")
	var res Result
	for _, c := range spec.Containers {
		if c.Image == "" {
			continue
		}
		if len(allowedRegistries) > 0 && !registryAllowed(allowedRegistries, c.Image) {
			res.Findings = append(res.Findings, deny(
				r.ID(), "high", c.Path+".image", c.Name,
				fmt.Sprintf("image %q is not from an approved registry (%s)", c.Image, fmtList(allowedRegistries))))
			continue
		}
		// Attestation is enforced only when the policy asks for it. Merely
		// configuring a trust store must not start denying every unused image:
		// administrators add signatures gradually before flipping the switch.
		if requireSignatures(cfg) && ctx != nil && ctx.TrustStore != nil {
			if ok, signer := trustedImage(ctx.TrustStore, c.Image); ok {
				_ = signer
				continue
			}
			res.Findings = append(res.Findings, deny(
				r.ID(), "high", c.Path+".image", c.Name,
				fmt.Sprintf("image %q has no valid attestation in the platform trust store", c.Image)))
		}
	}
	return res
}

func requireSignatures(cfg map[string]any) bool {
	v, ok := cfg["requireSignatures"].(bool)
	return ok && v
}

func registryAllowed(prefixes []string, image string) bool {
	ref := stripRegistryScheme(image)
	for _, prefix := range prefixes {
		prefix = stripRegistryScheme(prefix)
		if ref == prefix || strings.HasPrefix(ref, prefix+"/") {
			return true
		}
	}
	return false
}

func stripRegistryScheme(s string) string {
	s = strings.TrimPrefix(s, "https://")
	s = strings.TrimPrefix(s, "http://")
	return strings.TrimSuffix(s, "/")
}

func trustedImage(ts *policy.TrustStore, image string) (bool, string) {
	now := time.Now()
	for _, sig := range ts.Spec.Signatures {
		if sig.ExpiresAt != "" {
			exp, err := time.Parse(time.RFC3339, sig.ExpiresAt)
			if err != nil || !now.Before(exp) {
				continue
			}
		}
		if imageMatchesSignature(sig.Image, image) {
			return true, sig.Signer
		}
	}
	return false, ""
}

// imageMatchesSignature compares a signed image reference with an actual one.
// A digest signature matches only the same digest; a tag signature matches only
// the same explicit tag, never :latest (which can move at any time).
func imageMatchesSignature(signed, image string) bool {
	signed = strings.TrimSpace(signed)
	image = strings.TrimSpace(image)
	if signed == "" || image == "" {
		return false
	}
	if strings.Contains(signed, "@sha256:") {
		return signed == image
	}
	if strings.Contains(image, "@sha256:") || signed != image {
		return false
	}
	return !strings.HasSuffix(image, ":latest")
}

// --- image.digestOrPullAlways ------------------------------------------------------

type imagePinRule struct{}

func (imagePinRule) ID() string { return policy.RuleImageDigestOrPullAlways }

func (r imagePinRule) Evaluate(_ *Context, spec *workload.PodSpec, _ map[string]any, mutate bool) Result {
	var res Result
	for _, c := range spec.Containers {
		if c.Image == "" {
			continue
		}
		pullAlways := false
		if ps, ok := workload.GetString(c.Obj, "imagePullPolicy"); ok && ps == "Always" {
			pullAlways = true
		}
		if strings.Contains(c.Image, "@sha256:") {
			continue
		}
		tag := imageTag(c.Image)
		if pullAlways && tag != "latest" {
			continue
		}
		if mutate && tag != "latest" && tag != "" {
			// A digest cannot be invented, but pinning the pull policy stops a
			// re-pointed tag from being used without a fresh pull. :latest is
			// left alone because Always is already its default and changing
			// nothing would be a lie.
			c.Obj["imagePullPolicy"] = "Always"
			res.Findings = append(res.Findings, remediated(
				r.ID(), "medium", c.Path+".imagePullPolicy", c.Name,
				fmt.Sprintf("image %q is tag-pinned but may not be re-pulled", c.Image),
				"set imagePullPolicy to Always so a re-pointed tag is caught at restart"))
			res.Remediated++
			continue
		}
		res.Findings = append(res.Findings, deny(
			r.ID(), "medium", c.Path+".image", c.Name,
			fmt.Sprintf("image %q is not pinned by digest and imagePullPolicy is not Always; the tag can be re-pointed after review", c.Image)))
	}
	return res
}

func imageTag(image string) string {
	if i := strings.Index(image, "@"); i >= 0 {
		return ""
	}
	slash := strings.LastIndex(image, "/")
	colon := strings.LastIndex(image, ":")
	if colon > slash {
		return image[colon+1:]
	}
	return "latest"
}

// --- pod.serviceAccountToken -------------------------------------------------------

type saTokenRule struct{}

func (saTokenRule) ID() string { return policy.RuleServiceAccountToken }

func (r saTokenRule) Evaluate(_ *Context, spec *workload.PodSpec, _ map[string]any, mutate bool) Result {
	var res Result
	// Automounting the SA token is the default; a pod that does not opt out
	// hands every container a credential for the API server.
	automount, set := workload.GetBool(spec.Obj, "automountServiceAccountToken")
	if set && !automount {
		return res
	}
	// Individual containers cannot override automountServiceAccountToken; the
	// field lives on the pod (and on the service account).
	if mutate {
		workload.SetBool(spec.Obj, "automountServiceAccountToken", false)
		res.Findings = append(res.Findings, remediated(
			r.ID(), "medium", spec.FieldPath("automountServiceAccountToken"), "",
			"pod mounts a service account token by default",
			"set automountServiceAccountToken to false"))
		res.Remediated++
		return res
	}
	res.Findings = append(res.Findings, deny(
		r.ID(), "medium", spec.FieldPath("automountServiceAccountToken"), "",
		"pod does not set automountServiceAccountToken=false; every container receives an API credential"))
	return res
}

// --- object-level rules ------------------------------------------------------------

// ObjectRules are evaluated once per submitted object (not per pod spec) because
// they judge the object as a whole: unreadable templates, unknown kinds and
// malformed structure.
var ObjectRuleIDs = []string{
	policy.RuleUnknownWorkload,
	policy.RuleMalformedWorkload,
}

// EvaluateObject returns findings for object-level rules. The engine handles
// changing the disposition (deny/remediate/audit) based on policy action.
func EvaluateObject(ruleID string, w *workload.Workload) []policy.Finding {
	switch ruleID {
	case policy.RuleUnknownWorkload:
		if w.KnownKind {
			return nil
		}
		if len(w.SuspiciousPaths) > 0 {
			var out []policy.Finding
			for _, p := range w.SuspiciousPaths {
				out = append(out, deny(
					policy.RuleUnknownWorkload, "high", p, "",
					fmt.Sprintf("object of kind %s carries a container-shaped template at %s that could not be validated", w.GVK.Kind, p)))
			}
			return out
		}
		if w.HasPodSpecs() {
			advisory := finding(
				policy.RuleUnknownWorkload, "info", policy.ActionAudit, "", "",
				fmt.Sprintf("object of kind %s is not a known workload; %d embedded pod template(s) were found by structural scan and evaluated with the same rules", w.GVK.Kind, len(w.PodSpecs)))
			advisory.Advisory = true
			return []policy.Finding{advisory}
		}
		return nil
	case policy.RuleMalformedWorkload:
		var out []policy.Finding
		for _, p := range w.Problems {
			out = append(out, deny(
				policy.RuleMalformedWorkload, "high", "", "", p))
		}
		return out
	}
	return nil
}

// IsObjectRule reports whether id is evaluated once per object.
func IsObjectRule(id string) bool {
	for _, r := range ObjectRuleIDs {
		if r == id {
			return true
		}
	}
	return false
}
