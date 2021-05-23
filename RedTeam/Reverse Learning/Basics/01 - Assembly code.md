
# <u>Assembly code CheatSheet</u>

## Data Movement
| Instruction        | Description    
|:------------- |:-------------
|mov S,D|Move S to D
|push S|Push source onto stack
|pop D|Pop top of stack into destination
|cwtl|Convert word in %ax to doubleword in %eax (sign-extended)
|cltq|Convert doubleword in %eax to quadword in %rax (sign-extended)
|cqto|Convert quadword in %rax to octoword in %rdx:%rax

## Arythmetic operations
### <h3 style='color:grey'>Basic operations</h3>
| Instruction        | Description    
|:------------- |:-------------
|inc D|Increment by 1
|dec D|Decrement by 1
|neg D|Arithmetic negation
|not D|Bitwise complement

### <h3 style='color:grey'>Binaries operations</h3>
| Instruction        | Description    
|:------------- |:-------------
|leaq S, D|Load effective address of source into destination
|add S, D|Add source to destination
|sub S, D|Subtract source from destination
|imul S, D|Multiply destination by source
|xor S, D|Bitwise XOR destination by source
|or S, D|Bitwise OR destination by source
|and S, D|Bitwise AND destination by source

### <h3 style='color:grey'>Shifting operations</h3>
| Instruction        | Description    
|:------------- |:-------------
|sal / shl k, D|Left shift destination by k bits
|sar k, D|Arithmetic right shift destination by k bits
|shr k, D|Logical right shift destination by k bits

### <h3 style='color:grey'>Advanced operations</h3>
| Instruction        | Description    
|:------------- |:-------------
|imulq S|Signed full multiply of %rax by S Result stored in %rdx:%rax
|mulq S|Unsigned full multiply of %rax by S Result stored in %rdx:%rax
|idivq S|Signed divide %rdx:%rax by S Quotient stored in %rax Remainder stored in %rdx
|divq S|Unsigned divide %rdx:%rax by S Quotient stored in %rax Remainder stored in %rdx

## Comparisons 
| Instruction        | Description    
|:------------- |:-------------
|cmp S2 , S1|Set condition codes according to S1 - S2
|test S2 , S1|Set condition codes according to S1 & S2

## Conditions instructions

### <h3 style='color:grey'>Conditional instruction set</h3>
| Instruction        | Description    
|:------------- |:-------------
|sete / setz D |Set if equal/zero
|setne / setnz D |Set if not equal/nonzero
|sets D |Set if negative
|setns D |Set if nonnegative
|setg / setnle D |Set if greater (signed)
|setge / setnl D |Set if greater or equal (signed)
|setl / setnge D |Set if less (signed)
|setle / setng D |Set if less or equal
|seta / setnbe D| Set if above (unsigned)
|setae / setnb D| Set if above or equal (unsigned)
|setb / setnae D| Set if below (unsigned)
|setbe / setna D| Set if below or equal (unsigned)


### <h3 style='color:grey'>Jumps</h3>
| Instruction        | Description    
|:------------- |:-------------
|jmp|Label Jump to labe
|jmp \*Operand|Jump to specified location
|je / jz Label|Jump if equal/zero
|jne / jnz Label|Jump if not equal/nonzero
|js Label|Jump if negative
|jns Label|Jump if nonnegative
|jg / jnle Label|Jump if greater (signed)
|jge / jnl Label|Jump if greater or equal (signed)
|jl / jnge Label|Jump if less (signed)
|jle / jng Label|Jump if less or equal
|ja / jnbe Label|Jump if above (unsigned)
|jae / jnb Label|Jump if above or equal (unsigned)
|jb / jnae Label|Jump if below (unsigned)
|jbe / jna Label|Jump if below or equal (unsigned)

### <h3 style='color:grey'>Conditional moves</h3>
| Instruction        | Description    
|:------------- |:-------------
|cmove / cmovz S, D|Move if equal/zero
|cmovne / cmovnz S, D|Move if not equal/nonzero
|cmovs S, D|Move if negative
|cmovns S, D|Move if nonnegative
|cmovg / cmovnle S, D|Move if greater (signed)
|cmovge / cmovnl S, D|Move if greater or equal (signed)
|cmovl / cmovnge S, D|Move if less (signed)
|cmovle / cmovng S, D|Move if less or equal
|cmova / cmovnbe S, D|Move if above (unsigned)
|cmovae / cmovnb S, D|Move if above or equal (unsigned)
|cmovb / cmovnae S, D|Move if below (unsigned)
|cmovbe / cmovna S, D|Move if below or equal (unsigned)

## Procedure calls
| Instruction        | Description    
|:------------- |:-------------
|call \*Operand|Push return address and jump to specified location
|call Label|Push return address and jump to label
|leave|Set %rsp to %rbp, then pop top of stack into %rbp
|ret|Pop return address from stack and jump there
