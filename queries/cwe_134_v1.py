#============================================================================================================
# CWE-134 Uncontrolled Format String
#
# Vuln Info: This vulnerability comes from using printf without a modifier
# Ex: cgc_printf(message);          <--Bad
#     cgc_printf("%s", message);    <--Good
#
# Methodology: 
# 1. Check if file has a printf function
# 2. Check if any instructions use printf
# 3. Check if params in printf are data type(correct) or var_type(incorrect, no modifier i.e. %s used)
#
# Try it on: Barcoder, Checkmate, Kaprica_Go
#============================================================================================================

import sys
from grakn.client import Graph

def main(keyspace):
    graph = Graph(uri='http://localhost:4567', keyspace=keyspace)

    # Get address of printf to use for next query
    query1 ='match $func isa function, has func-name contains "printf", has asm-address $a; select $a;'
    result1 = graph.execute(query1)

    # If printf is found continue query
    for printf_func in result1:
        printf_addr = printf_func['a']['value']

        # Pull any instructions that use printf and don't use a modifier (have var type and not data type)
        func_addr = int(result1[0]['a']['value'], 16)
        query2 = 'match $x has operation-type "MLIL_CALL_SSA", has asm-address $a; $y isa "MLIL_CONST_PTR"; ($x,$y); $z isa constant, has constant-value {}; ($y,$z); $l isa "list", has list-size != 2; ($x,$l); $s isa "MLIL_VAR_SSA"; ($l,$s); offset 0; limit 30;select $x, $a;'.format(func_addr)
        result2 = graph.execute(query2)
        
        # If there is an instruction that uses printf without modifier, output instruction 
        if result2:
            for instr in result2:
                asm_addr = instr['a']['value']

                print("CWE-134: Uncontrolled Format String possible at {} ".format(asm_addr))

if __name__ == "__main__":
    if len(sys.argv) > 1:
        keyspace = sys.argv[1]
    else:
        keyspace = "grakn"
    main(keyspace)