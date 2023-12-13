import argparse
from concurrent.futures import ThreadPoolExecutor
from modules.getsub import GetSub

def query_module(module, getsub_instance):
    getattr(getsub_instance, f"query_{module}")()
    return getsub_instance.findings()

def main(args):
    if args.module == "getsub":
        if args.domain:
            modules_to_query = ["crtsh", "alienvault", "chaos", "cdx", "dnsdumpster",
                                "hackertarget", "securitytrails", "shodan", "virustotal"]

            init_module = GetSub(args.domain)

            with ThreadPoolExecutor(max_workers=len(modules_to_query)) as executor:
                results = list(executor.map(lambda m: query_module(m, init_module), modules_to_query))

            all_results = [subdomain for result in results for subdomain in result]

            for subdomain in all_results:
                print(subdomain)

            if args.output:
                with open(args.output, 'w') as output_file:
                    for subdomain in all_results:
                        output_file.write(subdomain + '\n')
                print(f"\n[ OUTPUT ] Results also saved to {args.output}")

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
