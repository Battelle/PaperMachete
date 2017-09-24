import sys
import subprocess
import os
from os.path import isdir
from os.path import basename, isfile,join
from os import listdir
import pmanalyze
import ConfigParser

ENTER = 'Press ENTER to continue'
PATH = os.path.abspath('.')
MACHETE = PATH
script_path = MACHETE+"/cwe_queries/"
configParser = ConfigParser.RawConfigParser()
configParser.read('config')
GRAKN = configParser.get('PATHS', 'GRAKN') 
GRAQL = '/graql_files'

def run_script(script_path, script):
    try:
        subprocess.call(["python3.6",script_path+script])
    except OSError:
        print("It looks like you don't have Python3.6 installed. " \
            "The Grakn Python driver requires it.")
        return -1
    return 0

def run(script):
    if script == 'all_scripts':
        scripts = [f for f in listdir(script_path) if isfile(join(script_path, f))]
        for script in scripts:
            if run_script(script_path, script): return
            print("Script " + script + " complete.")
        print("All scripts complete.")
    else:
        if isfile(join(script_path, script)):
            if run_script(script_path, script): return
        else:
            print("Could not find the python script " + script)
            print("Please make sure it is located in " + script_path)
        return

def main():
    menu = True
    while menu:
        subprocess.call("clear")
        print("""
 ____                        __  __            _          _
|  _ \ __ _ _ __  ___ _ __  |  \/  | __ _  ___| |__   ___| |_ ___
| |_) / _` | '_ \/ _ \ '__| | |\/| |/ _` |/ __| '_ \ / _ \ __/ _ \\
|  __/ (_| | |_)|  __/ |    | |  | | (_| | (__| | | |  __/ ||  __/
|_|   \__,_| .__/\___|_|    |_|  |_|\__,_|\___|_| |_|\___|\__\___|
           |_|                                             
""")

        #Check directories	
        if not isdir(GRAKN):
            if GRAKN == '':
                print('Please set the path to your Grakn installation in the config file.\n')
                print('Open the file called \'config\' in your paper machete folder, and set')
                print('the variable \'GRAKN\' to the full file path of your Grakn installation.')
            else:
                print('Grakn directory not found\n')
                print('Please ensure grakn is installed in ' + GRAKN)
            sys.exit()
        if not isdir(MACHETE):
            print('Paper Machete directory not found')
            print('Please ensure Paper Machete is installed in ' + PATH)
            sys.exit()
        if not isdir(MACHETE + GRAQL):
            print('Creating ' + GRAQL)
            subprocess.call(["mkdir", "graql_files"])

        graql = raw_input('[1] Run all scripts\n[2] Run specified script\n[3] Compile new .graql\n[4] Upload .graql file\n[5] Quit\n')  
        try:
            graql = int(graql)
            if graql == 1:
                run('all_scripts')
                raw_input(ENTER)
            elif graql == 2:
                run(str(raw_input('Please enter the name of the script to run: ')))
                raw_input(ENTER)
            elif graql == 3:
                binary = raw_input('Please enter the path to the file you wish to analyze: ')
                if not isfile(join(PATH, binary)) and not isfile(binary):
                    print("File {} not found".format(binary))
                else:
                    functions = str(raw_input('Please enter the functions to examine seperated by spaces.\nOr press enter without typing anything to examine all functions: ')).split()
                    pmanalyze.pmanalyze(binary, functions)
                raw_input(ENTER)
            elif graql == 4:
                file_name = raw_input('Please enter the name of the .graql file to upload: ')
                name, file_extension = os.path.splitext(file_name)
                if file_extension != ".graql":
                    file_name += '.graql'
                if not os.path.isfile(MACHETE + GRAQL + "/" + file_name):
                    print(file_name + ' not found in ' + MACHETE + GRAQL)
                    raw_input(ENTER)
                else:
                    print('Restarting Grakn. Press \"Y\" when prompted')
                    subprocess.call([GRAKN+"/bin/grakn.sh", "clean"])
                    subprocess.call([GRAKN+"/bin/grakn.sh", "start"])
                    try:
                        subprocess.call([GRAKN+"/bin/graql.sh", "-f", MACHETE + GRAQL + "/" +file_name])
                        print('Success!')
                        print('Please run paper_machete.py again and select [1] \"Run all scripts\" to check for vulnerabilities')
                        raw_input(ENTER)
                    except:
                        print('Upload failed, run [4] \"Upload .graql file\" again')
                        raw_input(ENTER)
            elif graql ==5:
                menu = False
            else:
                print("Invalid option")
                raw_input(ENTER)
        except ValueError:
            print("Invalid option")
            raw_input(ENTER)
if __name__ == "__main__":
    main()
