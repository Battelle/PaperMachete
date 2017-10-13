import sys
import subprocess
from os import listdir
from os.path import abspath, isdir, isfile, join, splitext
from ConfigParser import RawConfigParser
from mimetypes import guess_type
import pmanalyze

ENTER = '\nPress ENTER to continue'
MACHETE = abspath('.')
script_path = join(MACHETE, "queries")
configParser = RawConfigParser()
configParser.read('config')
GRAKN = configParser.get('PATHS', 'GRAKN') 
ANALYSIS = join(MACHETE, "analysis")

MENU1 = "[1] Analyze a binary file"
MENU2 = "[2] Migrate a JSON file into Grakn"
MENU3 = "[3] Run all CWE queries"
MENU4 = "[4] Clean and restart Grakn"
MENU5 = "[5] Quit"

def print_banner(title=""):
    subprocess.call("clear")
    print("""
 ____                        __  __            _          _           
|  _ \ __ _ _ __  ___ _ __  |  \/  | __ _  ___| |__   ___| |_ ___    ________
| |_) / _` | '_ \/ _ \ '__| | |\/| |/ _` |/ __| '_ \ / _ \ __/ _ \  /_______/
|  __/ (_| | |_)|  __/ |    | |  | | (_| | (__| | | |  __/ ||  __/  \_______\\
|_|   \__,_| .__/\___|_|    |_|  |_|\__,_|\___|_| |_|\___|\__\___|  /_______/
           |_|                                                     @==|;;;;;;>
""")
    total_len = 80
    if title:
        padding = total_len - len(title) - 4
        print("== {} {}\n".format(title, "=" * padding))
    else:
        print("{}\n".format("=" * total_len))

def run_script(script_path, script):
    try:
        subprocess.call(["python3.6", join(script_path, script)])
    except OSError:
        print("It looks like you don't have Python3.6 installed. " \
            "The Grakn Python driver requires it.")
        return -1
    return 0

def run(script):
    if script == 'all_scripts':
        print("Running all CWE queries against the 'grakn' keyspace...")
        scripts = [f for f in listdir(script_path) if isfile(join(script_path, f))]
        for script in scripts:
            if ".py" not in script: continue
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


def get_file_selection(types):
    file_list = listdir(ANALYSIS)
    filtered = []
    for file in file_list:
        if types == "json" and guess_type(join(ANALYSIS, file))[0] == "application/json":
            filtered.append(file)
        elif types == "bin":
            filecmd = (subprocess.check_output(["file", join(ANALYSIS, file)])).lower()
            if "elf" in filecmd or "mach-o" in filecmd or "pe" in filecmd or ".bndb" in file.lower():
                filtered.append(file)
        else:
            pass # not json or executable binary
        
    # print file choices
    if len(filtered) == 0:
        if types == "json":
            print("No json files were found in {}".format(ANALYSIS))
        elif types == "bin":
            print("No executable files were found in {}".format(ANALYSIS))
        raw_input(ENTER)
        return "quit"
    else:
        for i, file in enumerate(filtered):
            print "[{}] {}".format(i, file)

    index = raw_input('\nSelect a file number to analyze ([q]uit): ').lower()
    if index == "q" or index == "quit":
        return "quit"
    
    try:
        index = int(index)
        if index in range(0, len(filtered)):
            return filtered[int(index)]
    except ValueError:
        pass
    
    if index != "":
        print("\nThat is not a valid file selection. Try again.")
        raw_input(ENTER)
    if types == "bin":
        print_banner(MENU1)
    elif types == "json":
        print_banner(MENU2)
    else:
        print_banner()

    return False


def main():
    menu = True
    while menu:
        print_banner()

        # check directories	
        if not isdir(GRAKN):
            if GRAKN == '':
                print('Please set the path to your Grakn installation in the config file.\n')
                print('Open the file called \'config\' in your paper machete folder, and set')
                print('the variable \'GRAKN\' to the full file path of your Grakn installation.')
            else:
                print('Grakn directory not found\n')
                print('Please ensure grakn is located in ' + GRAKN)
            sys.exit()
        
        if not isdir(MACHETE):
            print('Paper Machete directory not found')
            print('Please ensure Paper Machete is located in ' + MACHETE)
            sys.exit()

        if not isdir(ANALYSIS):
            print("Creating directory '{}'".format(ANALYSIS))
            subprocess.call(["mkdir", "analysis"])

        menu_option = raw_input("{}\n{}\n{}\n{}\n{}\n\n>> ".format(MENU1,MENU2,MENU3,MENU4,MENU5))

        try:
            menu_option = int(menu_option)
        except ValueError:
            if menu_option != "":
                print("'{}' is not a valid option.".format(menu_option))
                raw_input(ENTER)
            continue

        # analyze a binary file
        if menu_option == 1:
            
            # display supported binary files in ./analysis
            binary = False
            while binary == False:
                print_banner(MENU1)
                binary = get_file_selection("bin")
                if binary == "quit":
                    break
            if binary == "quit":
                continue

            # check to see if the file exists, if it does, process it
            if not isfile(join(ANALYSIS, binary)):
                print("File '{}' not found.".format(binary))
            else:
                functions = str(raw_input('Specify a list of functions examine seperated by spaces (ENTER for all): ')).split()
                if functions == "":
                    pmanalyze.main(join(ANALYSIS, binary))
                else:
                    pmanalyze.main(join(ANALYSIS, binary), functions)
            raw_input(ENTER)
            
        # migrate a json file into Grakn
        elif menu_option == 2:

            # display supported binary files in ./analysis
            json = False
            while json == False:
                print_banner(MENU2)
                json = get_file_selection("json")
                if json == "quit":
                    break
            if json == "quit":
                continue
                
            try:
                # insert the ontology
                print("Inserting ontology into 'grakn' keyspace...")
                print("You'll see some inference rule data, that's normal.")
                subprocess.call([join(GRAKN, "bin", "graql.sh"), "-f", join(MACHETE, "templates", "binja_mlil_ssa.gql"), "-k", "grakn"])

                # migrate data into Grakn
                print("\nMigrating data from '{}' into 'grakn' keyspace...".format(json))
                print("This can take a while, so please wait! It will finish.")
                subprocess.call([join(GRAKN, "bin", "migration.sh"), "json", "--template", join(MACHETE, "templates", "binja_mlil_ssa.tpl"), "--active", "1", "--batch", "1", "--input", join(ANALYSIS, json), "--keyspace", "grakn"])

                print('Data successfully migrated into Grakn. You can now run CWE scripts to check for vulnerabilities')
                raw_input(ENTER)
            except:
                print('Upload failed... please try agin.')
                raw_input(ENTER)

        # run CWE queries
        elif menu_option == 3:
            run('all_scripts')
            raw_input(ENTER)

        # clean and restart Grakn
        elif menu_option == 4:
            print('Restarting Grakn. Press \"Y\" when prompted.\nWait until you see the Grakn banner before continuing!')
            raw_input(ENTER)
            subprocess.call([join(GRAKN, "bin", "grakn.sh"), "clean"])
            subprocess.call([join(GRAKN, "bin", "grakn.sh"), "start"])
            
        # quit
        elif menu_option == 5:
            menu = False

        else:
            print("Invalid option!\n")
            raw_input(ENTER)
        
if __name__ == "__main__":
    main()
