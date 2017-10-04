## Grakn JSON migration template for binja_mlil_ssa.ontology
insert

## Loop over all functions in the binary
for(<functions>) do {
    $f isa function
        has func-name <func_name>
        has asm-address <asm_addr>;

    ## Loop over all basic-blocks in this function and link basic-blocks to the function they are in
    for(<basic_blocks>) do {
        $<bb_name> isa basic-block
            has bb-name <bb_name>
            has bb-start <bb_start>
            has bb-end <bb_end>;
        (contains-basic-block: $<bb_name>, in-function: $f) isa has-basic-block;

        ## Loop over all instructions in this basic-block, add them, and link them to their basic-block
        for(<instructions>) do {
            $ins isa instruction
                has name <name>
                has il-index <il_index>
                has asm-address <asm_address>
                has operation-type <operation_type>;
            (contains-instruction: $ins, in-basic-block: $<in_bb>) isa has-instruction;
        
            ## NOTE: AST depth is a major concern here! We have to insert all
            ## depth 1 nodes in a instruction before depth 2 nodes can be linked to them.
            ## We assume our JSON nodes are sorted by depth so this will work.  
            ## The pmanalyze.py script does this for us. If you ever have issues
            ## with AST nodes under any instruction not being linked by a valid
            ## edge, ensuring the 'nodes' lists are ordered by 'depth' should
            ## be your first trouble shooting step!

            ## Loop over all nodes in this instruction and add them
            for(<nodes>) do {
                
                ## list nodes
                if (@equals(<node_type>, "list")) do {
                    $<name> isa <node_type>
                        has name <name>
                        has parent-hash <parent_hash>
                        has edge-label <edge_label>
                        has list-size <list_size>;
                        
                    if (<depth> > 1) do {
                        (from-node: $<parent_hash>, to-node: $<name>) isa node-link;
                    } else {
                        (from-node: $ins, to-node: $<name>) isa node-link;
                    }
                }

                ## constant nodes
                elseif (@equals(<node_type>, "constant")) do {
                    $<name> isa <node_type>
                        has name <name>
                        has parent-hash <parent_hash>
                        has edge-label <edge_label>
                        has constant-value <constant_value>;

                    if (<depth> > 1) do {
                        (from-node: $<parent_hash>, to-node: $<name>) isa node-link;
                    } else {
                        (from-node: $ins, to-node: $<name>) isa node-link;
                    }
                
                }

                ## variable-ssa nodes
                elseif (@equals(<node_type>, "variable-ssa")) do {
                    $<name> isa <node_type>
                        has name <name>
                        has parent-hash <parent_hash>
                        has edge-label <edge_label>
                        has var <var>
                        has version <version>
						has var-type <var_type>
						has var-size <var_size>
						has var-func <var_func>;

                    if (<depth> > 1) do {
                        (from-node: $<parent_hash>, to-node: $<name>) isa node-link;
                    } else {
                        (from-node: $ins, to-node: $<name>) isa node-link;
                    }
                }

                ## variable nodes
                elseif (@equals(<node_type>, "variable")) do {
                    $<name> isa <node_type>
                        has name <name>
                        has parent-hash <parent_hash>
                        has edge-label <edge_label>
                        has var <var>
						has var-type <var_type>
						has var-size <var_size>
						has var-func <var_func>;

                    if (<depth> > 1) do {
                        (from-node: $<parent_hash>, to-node: $<name>) isa node-link;
                    } else {
                        (from-node: $<parent_hash>, to-node: $<name>) isa node-link;
                    }
                }

                ## all other nodes (operations)
                else {
                    $<name> isa <node_type>
                        has name <name>
                        has parent-hash <parent_hash>
                        has edge-label <edge_label>;

                    if (<depth> > 1) do {
                        (from-node: $<parent_hash>, to-node: $<name>) isa node-link;
                    } else {
                        (from-node: $ins, to-node: $<name>) isa node-link;
                    }
                }
            }
        }
    }

    ## Loop over bb-edges and link the basic blocks in this function
    for(<bb_edges>) do {
        (from-basic-block: $<source>, to-basic-block: $<target>) isa basic-block-edge;
    }
}
