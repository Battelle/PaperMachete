import sys
import struct
import binaryninja as binja
from os.path import basename
from os.path import abspath
from collections import defaultdict

## Resulting Graql file targets Grakn v0.16.0

WRITE = True
gqlFile = None
insn_list = None
func_name =''
vars_and_sizes = {}

def process_function(func):
    global insn_list
    insn_list = []
    
    # Reset dict with variables and sizes
    global vars_and_sizes
    vars_and_sizes = {}
    
    func_name = func.name.replace('.', '_')
    asm_addr = hex(func.start).strip('L')
    stack = str(binja.function.Function.stack_layout.__get__(func))
    vars_and_sizes = get_variable_sizes(stack)

    print("Proccessing function: {}").format(func.name)

# Print vars and sizes for debugging
# for key, value in vars_and_sizes.items():
#       print ("Var: {} Size: {}".format(key, value))

    gql  = "\ninsert \n"
    gql += "$func_{0} isa function, has name \"{0}\", has asm-address \"{1}\", has stack \"{2}\"; \n".format(func_name, asm_addr, stack)
 
    if WRITE: gqlFile.write(gql)


def process_basic_block(func, block):
    func_name = func.name.replace('.', '_')

    gql  = "\nmatch \n"
    gql += "$func_{0} isa function, has name \"{0}\"; \n".format(func_name)
    gql += "\ninsert \n"
    gql += "$bb isa basic-block, has bb-start {}, has bb-end {}; \n".format(block.start, block.end-1)
    gql += "(contains-basic-block: $bb, in-function: $func_{}) isa has-basic-block; \n".format(func_name)
    
    if WRITE: gqlFile.write(gql)


def process_instruction(func, block, insn):
    func_name = func.name.replace('.', '_')

    # A single ISA instruction can map to many IL instructions.
    # This can cause the same instruction to be processed many times.
    # To avoid this, we track instructions in a function and only
    # process them once. We'll still catch all IL instructions.
    if insn.address not in insn_list:
        gql  = "\nmatch \n"
        gql += "$func_{0} isa function, has name \"{0}\"; \n".format(func_name)
        gql += "$bb isa basic-block, has bb-start {}, has bb-end {}; \n".format(block.start, block.end-1)
        gql += "(in-function: $func_{}, contains-basic-block: $bb) isa has-basic-block; \n".format(func_name)

        print("")
        print("=" * 50)

        if WRITE: gqlFile.write(gql)

        ast_parse([func, block, insn])
        insn_list.append(insn.address)


def ast_write_gql(args, name, il, level=0, edge=""):
    func  = args[0]
    block = args[1]
    insn  = args[2]

    ## AST TYPE KEY
    # I : Instruction
    # O : Operation
    # E : End (terminating) node
    # EC: End node - constant
    # ES: End node - SSA variable
    # EV: End noce - variable

    gql = ""
    et = ""

    func_name = func.name.replace('.', '_')

    # slice off the last "_#" and rejoin to get the parent reference hash
    parent = "_".join(name.split('_')[:-1])

    # Hashes of instruction nodes in the AST look like: "N_8735918103813_4195908c"
    # One element down from an instruction will look like: "N_8735918103813_4195908c_0"
    # So if there are two "_" in the hash, the node is an instruction. List nodes have
    # the letter 'L' appended to them. (Yeah, I LOL'd when I wrote this too.)
    if 'L' in parent:
        parent_type = "list"
        name = name.replace('L', 'N') # reset node status
    elif parent.count("_") == 2:
        parent_type = "instruction"
    else:
        parent_type = "operation"

    if isinstance(il, binja.MediumLevelILInstruction):
        print('Il String: {}').format(il)
        print('IL Size: {}').format(il.size)

        # instruction
        if level == 0:
            print("-" * 50)
            print("I  {}: {} ({}:{})").format(il.instr_index, str(il.operation).split('.')[1], block.start, block.end-1)

            gql = "\nmatch\n"
            gql += "$func_{0} isa function, has name \"{0}\"; \n".format(func_name)
            gql += "$bb isa basic-block, has bb-start {}, has bb-end {}; \n".format(block.start, block.end-1)
            gql += "(in-function: $func_{}, contains-basic-block: $bb) isa has-basic-block; \n".format(func_name)
            gql += "\ninsert\n"
            gql += "${} isa instruction, has hash \"{}\", has il-index {}, has asm-address \"0x{:x}\", has operation-type \"{}\", has ins-text \"{}\";\n".format(name, name, il.instr_index, il.address, str(il.operation).split('.')[1], il)
            gql += "(contains-instruction: ${}, in-basic-block: $bb) isa has-instruction; \n".format(name)
            
            if WRITE: gqlFile.write(gql)

        # operation
        else:
            print("O {}{} -> {}").format('    '*level, edge, str(il.operation).split('.')[1])

            gql = "\nmatch\n"
            gql += "${0} isa {1}, has hash \"{0}\"; \n".format(parent, parent_type)
            gql += "\ninsert\n"
            gql += "${} isa {}, has hash \"{}\", has edge-label \"{}\";\n".format(name, str(il.operation).split('.')[1], name, edge)
            gql += "(to-node: ${}, from-node: ${}) isa node-link; \n".format(name, parent)

            if WRITE: gqlFile.write(gql)
            
        # edge
        for i, o in enumerate(il.operands):
            try:
                edge_label = il.ILOperations[il.operation][i][0]
            except IndexError:
                # Addresses issue in binja v1.1 stable with MLIL_SET_VAR_ALIASED 
                # operations in the Python bindings. 
                # See: https://github.com/Vector35/binaryninja-api/issues/787 
                edge_label = "unimplemented"
            child_name = "{}_{}".format(name, i)
            ast_write_gql(args, child_name, o, level+1, edge_label)
            
    # list of operands
    elif isinstance(il, list):
        print "L {}{}: list (len: {})".format('    '*level, edge, len(il))

        name = name.replace('N', 'L') # list hashes have an 'L' prefix to distinguish from nodes ('N').
        gql = "\nmatch\n"
        gql += "${0} isa {1}, has hash \"{0}\"; \n".format(parent, parent_type)
        gql += "\ninsert\n"
        gql += "${0} isa list, has hash \"{0}\", has list-size {1}, has edge-label \"{2}\";\n".format(name, len(il), edge)
        gql += "(to-node: ${}, from-node: ${}) isa node-link; \n".format(name, parent)

        if WRITE: gqlFile.write(gql)

        for i, item in enumerate(il):
            edge_label = i
            item_name = "{}_{}".format(name, i)
            ast_write_gql(args, item_name, item, level+1, edge_label)
            
    # end node
    else:

        gql += "\nmatch\n"
        gql += "${0} isa {1}, has hash \"{0}\"; \n".format(parent, parent_type)
        gql += "\ninsert\n"

        # constant
        if isinstance(il, long):
            (signed, ) = struct.unpack("l", struct.pack("L", il))
            il_str = "{:d} ({:#x})".format(signed, il)
            et = "C"
            gql += "${0} isa constant, has hash \"{0}\", has constant-value \"{1}\", has edge-label \"{2}\";\n".format(name, il, edge)
        
        # SSAVariable (not using type information)
        elif isinstance(il, binja.mediumlevelil.SSAVariable):
            il_str = "{}#{}".format(il.var, il.version)
            et = "S"
            var_type = il.var.type
            var_size = vars_and_sizes.get(str(il.var), 4) 
            var_func = func_name

            gql += "${0} isa variable-ssa, has hash \"{0}\", has var \"{1}\", has version {2}, has edge-label \"{3}\", has var-type \"{4}\", has var-size {5}, has var-func \"{6}\";\n".format(name, il.var, il.version, edge, var_type, var_size, var_func)

        # Variable (contains more information than we currently use)
        elif isinstance(il, binja.function.Variable):
            il_str = str(il)
            et = "V"
            var_type = il.type
            var_size = vars_and_sizes.get(str(il), 4) 
            var_func = func_name 

            gql += "${0} isa variable, has hash \"{0}\", has var \"{1}\", has edge-label \"{2}\", has var-type \"{3}\", has var-size {4}, has var-func \"{5}\";\n".format(name, il, edge, var_type, var_size, var_func)

        # Unknown terminating node (this should not be reached)
        else:
            print("A terminating node was encountered that was not expected: '{}'").format(type(il))
            raise ValueError

        gql += "(to-node: ${}, from-node: ${}) isa node-link; \n".format(name, parent)

        print("E{}{}{} -> {}").format(et, '    '*level, edge, il_str)

        if WRITE: gqlFile.write(gql)
        

def ast_name_elemet(args, il_type, il):
    h = hash(il)
    name = "N_{}_{}".format(h, il.address)
    child_name = "{}c".format(name)
    ast_write_gql(args, child_name, il)


def ast_parse(args):
    func = args[0]
    block = args[1]
    insn = args[2]

    print ("  function: {} (asm-addr: {})").format(func.name, hex(insn.address).strip('L'))
    lookup = defaultdict(lambda: defaultdict(list))

    for block in func.medium_level_il.ssa_form:
        for mil in block:
            lookup['MediumLevelILSSA'][mil.address].append(mil)

    for il_type in sorted(lookup):
        ils = lookup[il_type][insn.address]
        for il in sorted(ils):
            ast_name_elemet(args, il_type, il)

def process_edges(func):
    for block in func.medium_level_il.ssa_form:
        if len(block.outgoing_edges) > 0:
            for edge in block.outgoing_edges:
                func_name = (func.name).replace('.', '_')
                gql  = "\nmatch \n"
                gql += "$func_{0} isa function, has name \"{0}\"; \n".format(func_name)
                gql += "$frombb isa basic-block, has bb-end {}, has bb-start {}; \n".format(edge.source.end-1, edge.source.start)
                gql += "$tobb   isa basic-block, has bb-end {}, has bb-start {}; \n".format(edge.target.end-1, edge.target.start)
                gql += "(contains-basic-block: $frombb, in-function: $func_{}) isa has-basic-block; \n".format(func_name)
                gql += "(contains-basic-block: $tobb, in-function: $func_{}) isa has-basic-block; \n".format(func_name)
                gql += "\ninsert \n"
                gql += "(from-basic-block: $frombb, to-basic-block: $tobb) isa basic-block-edge; \n"

                if WRITE: gqlFile.write(gql)


def analyze(bv, func_list=[]):
    processed = 0
    list_len = len(func_list)

    for func in bv.functions:
        if list_len > 0 and func.name not in func_list: continue
        process_function(func)
        processed += 1

        ## process basic blocks
        for block in func.medium_level_il.ssa_form:
            process_basic_block(func, block)

            ## process instructions
            for insn in block:
                process_instruction(func, block, insn)

        ## process basic block edges
        # all edges need to exist in Grakn before we can do this
        # because edges stemming from loops wont have an associated
        # basic block inserted to create a relationship for.
        process_edges(func)

    if list_len > 0 and processed != list_len:
        print("\nWARNGING: Not all functions you specified were found!")
        print("We found and processed {} of the {} function(s) you specified.").format(processed, list_len)


# Helper method for get_variable_sizes
# Use this method to calculate var offset. var_90, __saved_edi -->   144, -1    
def get_offset_from_var(var):
    instance = False
    i=0

    # Parse string
    i = var.rfind(' ')+1
    tmp = var[i:-1]

    # Parse var
    if tmp[0] == 'v':
        tmp = tmp[4:]
        j = tmp.find('_')

        # Handles SSA var instances (var_14_1) and converts c, 58, 88 --> 12, 88, 136
        if (j != -1):
            tmp = tmp[:j]
            instance = True
        else:
            instance = False

    try:    
        tmp = int(tmp, 16)
    except:
        tmp = -1

    # -1 for non vars
    else:
        tmp = -1
    
    return tmp, instance 


# Accepts a string of stack variables, returns a dict of var names and sizes
# Called from process_function
def get_variable_sizes(stack):
    prev_offset = 0
    offset = 0
    counter = 0
    i=0
    var_dict = {}
    str_list = list(reversed(stack[1:-1].split(', ')))

    # Loop through each item on stack backwards
    for item in str_list:
        size=0
        tmp=0
        instance = False

        # Handle args and return addr
        if (('arg' in item) or ('return' in item)):
            size = 4

        elif('int32' in item):
            size = 4
            tmp, instance = get_offset_from_var(str_list[counter])
            if tmp != -1:
                offset = tmp
            if not instance:
                offset = prev_offset+4

        elif ('int64' in item):
            size = 8
            tmp, instance = get_offset_from_var(str_list[counter])
            if not instance:
                offset = prev_offset+8
            if tmp != -1:
                offset = tmp

        else:
            offset, instance = get_offset_from_var(str_list[counter])
            if instance:
                offset = offset-4

        if size == 0:  
            size = offset-prev_offset
        if (not instance):   
            prev_offset = offset

        # Parse string
        i = item.rfind(' ')+1
        key = item[i:-1]
        
        var_dict.update({key:size})
        counter = counter+1
    return var_dict


def pmanalyze(target, func_list):
    global WRITE
    global gqlFile

    PATH = abspath('.')
    ontology_file = PATH + "/binja_mlil_ssa.ontology"
    GRAQL = PATH + "/graql_files/" + basename(target)

    if WRITE:
        try:
            f = open('{}'.format(ontology_file), 'r')
            ontology = f.read()
            f.close
        except IOError:
            print("ERROR: Unable to read ontology file ('{}'). Exiting.").format(ontology_file)
            return

        try:
            gqlFile = open("{}.graql".format(GRAQL), "w")
        except IOError:
            print("ERROR: Unable to open {}.graql for writing.").format(GRAQL)
            return

        gqlFile.write(ontology)

    bv = binja.BinaryViewType.get_view_of_file(target)
    analyze(bv, func_list)

    if WRITE: gqlFile.close()
    if WRITE: print("\nGraql file '{}.graql' is ready.\n").format(basename(target))


if __name__ == "__main__":
    if len(sys.argv) > 1:
        target = sys.argv[1]
        func_list = sys.argv[2:]
        pmanalyze(target, func_list)
    else:
        print("Usage: {} <binary> [function1 function2 ...]").format(sys.argv[0])
