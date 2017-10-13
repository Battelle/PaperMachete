## Grakn JSON migration template for binja_mlil_ssa.gql : links instructions to their basic-blocks

## Loop over all functions in the binary
for(<functions>) do {

    ## Loop over all basic-blocks in this function and link basic-blocks to the function they are in 
    for(<basic_blocks>) do {
        
        ## Loop over all instructions in this basic-block, add them, and link them to their basic-block
        for(<instructions>) do {
            match 
            $bb isa basic-block
                has bb-name <in_bb>;
            
            $ins isa instruction
                has name <name>
                has il-index <il_index>
                has asm-address <asm_address>
                has operation-type <operation_type>;

            insert
            (contains-instruction: $ins, in-basic-block: $bb) isa has-instruction;
        }
    }
}
