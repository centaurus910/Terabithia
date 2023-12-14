import argparse
from modules.getsub import GetSub

def main(args):
    if args.module == "getsub":
        if args.domain:
            init_module = GetSub(args.domain)
            init_module.query_crtsh()
            init_module.query_alienvault()
            init_module.query_chaos()
            init_module.query_cdx()
            init_module.query_dnsdumpster()
            init_module.query_facebook_ct()
            init_module.query_hackertarget()
            init_module.query_securitytrails()
            init_module.query_shodan()
            init_module.query_virustotal()
            results = init_module.findings()

            # Print results to the console
            for subdomain in results:
                print(subdomain)

            # Write results to the specified output file (if provided)
            if args.output:
                with open(args.output, 'w') as output_file:
                    for subdomain in results:
                        output_file.write(subdomain + '\n')
                print(f"Results also saved to {args.output}")

            init_module.stats()
            init_module.report_logs()
    else:
        print("Pass at this point")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Tool description")

    parser.add_argument("module", choices=["getsub"], help="Specify the module to run")
    parser.add_argument("domain", help="Specify the domain to analyze")
    parser.add_argument("-o", "--output", help="Specify the output file path")

    args = parser.parse_args()
    main(args)
