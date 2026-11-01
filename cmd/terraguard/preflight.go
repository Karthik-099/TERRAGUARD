package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/Karthik-099/TERRAGUARD/engine"
)

// runPreflight checks a plan against live cloud quotas before apply. Quotas
// are enforced only when resources are created, so this is the one check that
// needs read-only cloud access; it is kept out of the deterministic scan.
func runPreflight(args []string) (int, error) {
	fs := flag.NewFlagSet("preflight", flag.ContinueOnError)
	plan := fs.String("plan", "", "terraform show -json output (required)")
	live := fs.Bool("live", false, "read limits and usage with the aws, az and gcloud CLIs (read-only calls)")
	quotas := fs.String("quotas", "", "JSON file of known limits and usage, keyed like the output, instead of --live")
	region := fs.String("region", firstEnv("AWS_REGION", "AWS_DEFAULT_REGION"), "AWS region when the provider's region is not a literal")
	format := fs.String("format", "text", "stdout format: text, json or markdown")
	mdOut := fs.String("markdown", "", "also write a Markdown report to this file")
	jsonOut := fs.String("json", "", "also write the JSON report to this file")
	if err := fs.Parse(args); err != nil {
		return 2, err
	}
	if *plan == "" {
		return 2, errors.New("usage: terraguard preflight --plan plan.json [--live | --quotas quotas.json]")
	}
	raw, err := os.ReadFile(*plan)
	if err != nil {
		return 2, err
	}
	demands, err := engine.QuotaDemands(string(raw), *region)
	if err != nil {
		return 2, err
	}
	usage := map[string]engine.QuotaUsage{}
	if *quotas != "" {
		b, err := os.ReadFile(*quotas)
		if err != nil {
			return 2, err
		}
		if err := json.Unmarshal(b, &usage); err != nil {
			return 2, fmt.Errorf("%s: %w", *quotas, err)
		}
	}
	var notes []string
	if *live {
		for _, d := range demands {
			if _, known := usage[d.Key]; known {
				continue
			}
			u, err := liveUsage(d)
			if err != nil {
				notes = append(notes, fmt.Sprintf("%s: %v", d.Key, err))
				continue
			}
			usage[d.Key] = u
		}
	}
	results := engine.CheckQuotas(demands, usage)
	buckets := engine.NewBucketNames(string(raw))
	if *live {
		for i := range buckets {
			buckets[i].Status = bucketStatus(buckets[i].Name)
		}
	}
	md := preflightMarkdown(results, notes) + bucketsMarkdown(buckets)
	b, _ := json.MarshalIndent(map[string]any{"results": results, "buckets": buckets, "notes": notes}, "", "  ")
	if err := writeIf(*mdOut, md); err != nil {
		return 2, err
	}
	if err := writeIf(*jsonOut, string(b)+"\n"); err != nil {
		return 2, err
	}
	switch *format {
	case "json":
		fmt.Println(string(b))
	case "markdown":
		fmt.Print(md)
	default:
		fmt.Print(preflightText(results, notes) + bucketsText(buckets))
	}
	for _, r := range results {
		if r.Status == "exceeds" {
			return 1, nil
		}
	}
	for _, bk := range buckets {
		if bk.Status == "taken" || bk.Status == "exists" {
			return 1, nil
		}
	}
	return 0, nil
}

// bucketStatus asks S3 whether a name is free: 404 free, 403 owned by another
// account, success means a bucket you can see already has the name.
func bucketStatus(name string) string {
	_, err := runCLI("aws", "s3api", "head-bucket", "--bucket", name)
	switch {
	case err == nil:
		return "exists"
	case strings.Contains(err.Error(), "404") || strings.Contains(err.Error(), "Not Found"):
		return "free"
	case strings.Contains(err.Error(), "403") || strings.Contains(err.Error(), "Forbidden"):
		return "taken"
	}
	return "unknown"
}

var bucketWhy = map[string]string{
	"taken":   "owned by another AWS account; apply would fail",
	"exists":  "already exists in your account; import it or rename, apply would fail",
	"free":    "available",
	"unknown": "not checked (run with --live)",
}

func bucketsText(bs []engine.BucketName) string {
	var b strings.Builder
	for _, bk := range bs {
		fmt.Fprintf(&b, "%-8s s3://%s (%s): %s\n", strings.ToUpper(bk.Status), bk.Name, bk.Address, bucketWhy[bk.Status])
	}
	return b.String()
}

func bucketsMarkdown(bs []engine.BucketName) string {
	if len(bs) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("\n| Status | S3 bucket name | Resource |\n|---|---|---|\n")
	for _, bk := range bs {
		fmt.Fprintf(&b, "| %s | %s | %s |\n", strings.ToUpper(bk.Status), bk.Name, bk.Address)
	}
	return b.String()
}

func preflightText(rs []engine.QuotaResult, notes []string) string {
	if len(rs) == 0 {
		return "The plan creates nothing that counts against the quotas TerraGuard checks.\n"
	}
	var b strings.Builder
	exceeds := 0
	for _, r := range rs {
		switch r.Status {
		case "exceeds":
			exceeds++
			fmt.Fprintf(&b, "EXCEEDS  %-46s needs %s, %s free (limit %s, used %s)\n", r.Key, num(r.Need), num(r.Free), num(r.Limit), num(r.Used))
		case "ok":
			fmt.Fprintf(&b, "ok       %-46s needs %s, %s free\n", r.Key, num(r.Need), num(r.Free))
		default:
			fmt.Fprintf(&b, "unknown  %-46s needs %s (no limit data)\n", r.Key, num(r.Need))
		}
	}
	for _, n := range notes {
		fmt.Fprintf(&b, "note: %s\n", n)
	}
	for _, r := range rs {
		if r.Status == "unknown" {
			b.WriteString("\nUnknown quotas: run with --live (read-only cloud credentials) or --quotas FILE; pass --region if the region shows as unknown.\n")
			break
		}
	}
	if exceeds > 0 {
		fmt.Fprintf(&b, "\n%d quota(s) would be exceeded: apply would fail partway through. Request an increase or reduce the plan.\n", exceeds)
	}
	return b.String()
}

func preflightMarkdown(rs []engine.QuotaResult, notes []string) string {
	var b strings.Builder
	b.WriteString("### TerraGuard quota preflight\n\n")
	if len(rs) == 0 {
		b.WriteString("The plan creates nothing that counts against the quotas TerraGuard checks.\n")
		return b.String()
	}
	b.WriteString("| Status | Quota | Region | Needs | Free | Limit |\n|---|---|---|---|---|---|\n")
	for _, r := range rs {
		free, limit := "-", "-"
		if r.Status != "unknown" {
			free, limit = num(r.Free), num(r.Limit)
		}
		est := ""
		if r.Estimated {
			est = " (estimated from sizes)"
		}
		fmt.Fprintf(&b, "| %s | %s%s | %s | %s | %s | %s |\n", strings.ToUpper(r.Status), r.Title, est, r.Region, num(r.Need), free, limit)
	}
	for _, n := range notes {
		fmt.Fprintf(&b, "\n> %s", n)
	}
	b.WriteString("\n")
	return b.String()
}

func num(f float64) string { return strconv.FormatFloat(f, 'f', -1, 64) }

func writeIf(path, s string) error {
	if path == "" {
		return nil
	}
	return os.WriteFile(path, []byte(s), 0o644)
}

func firstEnv(keys ...string) string {
	for _, k := range keys {
		if v := os.Getenv(k); v != "" {
			return v
		}
	}
	return ""
}

// runCLI runs a cloud CLI with a timeout; tests replace it.
var runCLI = func(name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).Output()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) && len(ee.Stderr) > 0 {
			return nil, fmt.Errorf("%s: %s", name, strings.TrimSpace(string(ee.Stderr)))
		}
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	return out, nil
}

// awsUsageQueries count current usage for each AWS quota code.
var awsUsageQueries = map[string][]string{
	"L-F678F1CE": {"ec2", "describe-vpcs", "--query", "length(Vpcs)"},
	"L-0263D0A3": {"ec2", "describe-addresses", "--query", "length(Addresses)"},
	"L-A4707A72": {"ec2", "describe-internet-gateways", "--query", "length(InternetGateways)"},
	"L-53DA6B97": {"elbv2", "describe-load-balancers", "--query", "length(LoadBalancers[?Type=='application'])"},
	"L-7B6409FD": {"rds", "describe-db-instances", "--query", "length(DBInstances)"},
	"L-DC2B2D3D": {"s3api", "list-buckets", "--query", "length(Buckets)"},
}

func liveUsage(d engine.QuotaDemand) (engine.QuotaUsage, error) {
	if d.Region == "unknown" {
		return engine.QuotaUsage{}, errors.New("region unknown; pass --region")
	}
	switch d.Cloud {
	case "aws":
		service, code, _ := strings.Cut(d.Quota, "/")
		limit, err := awsLimit(service, code, d.Region)
		if err != nil {
			return engine.QuotaUsage{}, err
		}
		used, err := awsUsed(code, d.Region)
		return engine.QuotaUsage{Limit: limit, Used: used}, err
	case "azure":
		cmd := []string{"vm", "list-usage", "--location", d.Region, "-o", "json"}
		if d.Quota == "PublicIPAddresses" {
			cmd = []string{"network", "list-usages", "--location", d.Region, "-o", "json"}
		}
		out, err := runCLI("az", cmd...)
		if err != nil {
			return engine.QuotaUsage{}, err
		}
		var rows []struct {
			Name struct {
				Value string `json:"value"`
			} `json:"name"`
			CurrentValue json.Number `json:"currentValue"`
			Limit        json.Number `json:"limit"`
		}
		if err := json.Unmarshal(out, &rows); err != nil {
			return engine.QuotaUsage{}, err
		}
		for _, r := range rows {
			if strings.EqualFold(r.Name.Value, d.Quota) {
				used, _ := r.CurrentValue.Float64()
				limit, _ := r.Limit.Float64()
				return engine.QuotaUsage{Limit: limit, Used: used}, nil
			}
		}
		return engine.QuotaUsage{}, fmt.Errorf("az reports no %s quota in %s", d.Quota, d.Region)
	case "gcp":
		out, err := runCLI("gcloud", "compute", "regions", "describe", d.Region, "--format=json")
		if err != nil {
			return engine.QuotaUsage{}, err
		}
		var reg struct {
			Quotas []struct {
				Metric string  `json:"metric"`
				Limit  float64 `json:"limit"`
				Usage  float64 `json:"usage"`
			} `json:"quotas"`
		}
		if err := json.Unmarshal(out, &reg); err != nil {
			return engine.QuotaUsage{}, err
		}
		for _, q := range reg.Quotas {
			if q.Metric == d.Quota {
				return engine.QuotaUsage{Limit: q.Limit, Used: q.Usage}, nil
			}
		}
		return engine.QuotaUsage{}, fmt.Errorf("gcloud reports no %s quota in %s", d.Quota, d.Region)
	}
	return engine.QuotaUsage{}, fmt.Errorf("no live lookup for %s", d.Cloud)
}

// awsLimit returns the applied quota, or the AWS default when none is applied.
func awsLimit(service, code, region string) (float64, error) {
	for _, op := range []string{"get-service-quota", "get-aws-default-service-quota"} {
		out, err := runCLI("aws", "service-quotas", op, "--service-code", service, "--quota-code", code, "--region", region, "--query", "Quota.Value", "--output", "text")
		if err == nil {
			if v, perr := strconv.ParseFloat(strings.TrimSpace(string(out)), 64); perr == nil {
				return v, nil
			}
		}
		if op == "get-aws-default-service-quota" {
			return 0, fmt.Errorf("could not read %s/%s: %v", service, code, err)
		}
	}
	return 0, nil
}

func awsUsed(code, region string) (float64, error) {
	if code == "L-1216C47A" {
		out, err := runCLI("aws", "ec2", "describe-instances", "--region", region, "--filters", "Name=instance-state-name,Values=pending,running",
			"--query", "Reservations[].Instances[].[InstanceType,CpuOptions.CoreCount,CpuOptions.ThreadsPerCore]", "--output", "json")
		if err != nil {
			return 0, err
		}
		var rows [][]any
		if err := json.Unmarshal(out, &rows); err != nil {
			return 0, err
		}
		total := 0.0
		for _, r := range rows {
			if len(r) != 3 {
				continue
			}
			typ, _ := r[0].(string)
			cores, _ := r[1].(float64)
			threads, _ := r[2].(float64)
			if _, std := engine.AWSInstanceVCPUs(typ); std {
				total += cores * max(threads, 1)
			}
		}
		return total, nil
	}
	q, ok := awsUsageQueries[code]
	if !ok {
		return 0, fmt.Errorf("no usage query for %s", code)
	}
	out, err := runCLI("aws", append(q, "--region", region, "--output", "text")...)
	if err != nil {
		return 0, err
	}
	return strconv.ParseFloat(strings.TrimSpace(string(out)), 64)
}
