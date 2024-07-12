#!/usr/bin/env python3

import os
import subprocess
import sys
import aiofiles
import asyncio
from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor
import argparse

def create_directory(target):
    if not os.path.exists(target):
        os.makedirs(target)
    os.chdir(target)

def run_command(command, outputfile):
    with open(outputfile, 'a') as f:
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        for line in process.stdout:
            f.write(line.decode())
        process.wait()

async def merge_files(output_files, merged_file):
    async with aiofiles.open(merged_file, 'w') as outfile:
        for name in tqdm(output_files, desc="Merging files", unit="file"):
            async with aiofiles.open(name, 'r') as infile:
                content = await infile.read()
                await outfile.write(content)

async def filter_urls(input_file, target):
    async with aiofiles.open(input_file, 'r') as infile:
        unique_urls = set(await infile.readlines())
    
    sorted_urls = sorted(unique_urls)

    async with aiofiles.open(f"unique_urls.txt", 'w') as outfile:
        await outfile.writelines(sorted_urls)

    parameters = set()
    for url in sorted_urls:
        if '?' in url:
            params = url.split('?')[1].split('&')
            parameters.update(params)

    async with aiofiles.open(f"{target}_parameters.txt", 'w') as param_file:
        await param_file.writelines(f"{param}\n" for param in parameters)

    async with aiofiles.open(f"unique_urls.txt", 'r') as infile:
        async with aiofiles.open(f"{target}_urls_with_params.txt", 'w') as with_params, aiofiles.open(f"{target}_urls_without_params.txt", 'w') as without_params:
            async for line in infile:
                if '=' in line:
                    await with_params.write(line)
                else:
                    await without_params.write(line)

async def probe_urls(input_file, output_file):
    command = f"httpx -l {input_file} -o {output_file} -silent"
    process = await asyncio.create_subprocess_shell(command)
    await process.communicate()

async def main(target):
    create_directory(target)

    commands = [
        f"subfinder -d {target} | tee -a subfinder.txt",
        f"assetfinder --subs-only {target} | tee -a assetfinder.txt",
        f"amass enum -passive -d {target} | tee -a amass.txt",
        f"waybackurls {target} | tee -a waybackurls.txt",
        f"getallurls {target} | tee -a getallurls.txt",
        f"gau {target} | tee -a gau.txt",
        f"katana -u {target} -kf 3 | tee -a katana.txt"
    ]

    with ThreadPoolExecutor(max_workers=10) as executor:
        list(tqdm(executor.map(lambda cmd: run_command(*cmd.split("| tee -a ")), commands), total=len(commands), desc="Running commands"))

    await merge_files(["subfinder.txt", "assetfinder.txt", "amass.txt", "waybackurls.txt", "getallurls.txt", "gau.txt", "katana.txt"], "output.txt")

    await filter_urls("output.txt", target)

    print("Probing URLs with httpx...")
    await probe_urls("unique_urls.txt", "live_urls.txt")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='URL and parameter enumeration script for testing the target website.')
    parser.add_argument('target', help='The target website to enumerate.')
    args = parser.parse_args()

    target = args.target
    asyncio.run(main(target))
