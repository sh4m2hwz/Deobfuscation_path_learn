RU:

Reverse Deobfuscation]:{
	1) IDA PRO BOOK
	2) IDAPython -> IDAPython book + internal work,articles
	3) solves all CRACKME tasks
	4) learn symbex and taint analysis and others
	(1) symbex/SAT/SMT: https://sat-smt.codes/ SAT/SMT_by_Example.pdf;остальную литературу(смотри в SMT_SAT_Solvers_theory.zip)
	(2) taint analysis: libdft; https://github.com/wmkhoo/taintgrind; и др
	5) learn triton
	6) learn BAP
	7) Intel PIN
	8) DynamoRIO это тот же самый Intel PIN,только для больше архитектур+больше функционала
	
end target: themida,tigrass 7 task
end target2: create && dev self-modification code library private

program Deobfuscation:
[1 string obfuscation]:
	1) string blinding/encryption
	2) string unfolding
	3) string JIT runtime gen block string unfolding/decryption
[2 constant obfuscation]:
	constant: IMM,DISP
	1) constant folding
	2) constant unfolding
	3) constant blinding
	4) constant unfolding && blinding
[3 junk instructions/blocks obfuscation]:
	junk obfuscation: недосегаемые инструкции/блоки,которые никогда не исполняться.
	1) junk insns
	2) junk BBs(BasicBlocks)
	3) junk DDBs(Data Dependence Blocks)
	4) junk Src Level blocks
	5) junk Api calls
	6) junk Api call blocks
[4 mutation instruction/blocks obfuscation]:
	1) mutation insn
	2) mutation BBs(BasicBlocks)
	3) mutation DDBs(Data Dependence Blocks)
	4) mutation construct src level blocks
[5 opaque predicates obfuscation]:
	(1) static opaque predicates:
		1) invariant opaque predicates
		2) contextual opaque predicates
	(2) dynamic opaque predicates:
		1) invariant opaque predicates
		2) contextual opaque predicates
	(3) adjacent/non-contiguous opaque predicates
	(4) mixing types opaque predicates
[6 self-modification code]:
self-modifier block ; MB()
{
; ...
} ; блок который производит модификации блока self-modificated block
	
self-modificated block ; MDB()
{
; ...
} ; блок который модифицируется блоком self-modifier block

	(1) [построение self-modification code по структуре и компоновке && заимодействия MB();MDB()]:{
	1) MB(),MDB() инлайнятся в друг друга
	2) MB(),MDB() разделяются на 2 блока,исполняются в одном потоке
	3) MB(),MDB() разделяются на 2 блока,исполняются в каждом своём потоке паралельно создавая race condition,где MB() опережает поток MDB(),в патчинге инструкций(MB() поток модфицирует инструкции,MDB() поток исполняет модифицированные инструкции ,приведенные к валидной семантике алгоритма)
}
	(2) [построение конструкции модификации MDB() в MB()]:{
	1) через инструкции передачи управления переход на opcode fields,opcodes,imm,disp инструкции
	2) невалидные инструкции ,которые преобразуются нп уровне опкодов,битовых полей пермутаций существующих байтов в MDB()
	3) невалидные инструкции,для которых пораждаются опкоды или битовые поля ,в ходе построение кодирование семантики инструкции через пермутацию байтов и конкатенацию битов мутация этих операций
	4) невалидные инструкции,для которых поражадются новые невалидные опкоды,которые битовыми операциями,бинарными,векторными инструкциями происходит приведение к валидным инструкциям (выражение изначально заданой семантики исходя из существующей эвристики,пораждая динамически сигнатуры(кодировку,опкоды))
	5) метаморфизм - пораждение новой эвристики,сигнатур: опкодов,битовых полей в рантайме (JIT), заблинденных(невалидных) и приведение их к валидным опкодам + формирование целевой инструкции (мутация всех операций приведений)
}
[7 INDIRECT BRANCH]:
	1) mutation or unfolding && blinding runtime generate validate address
	2) таблица переходов,которая вычисляется в рантайме:
		1) адреса могут быть накрыты семмитричным шифрованием
		2) адреса развертываются и вычисляются в рантайме,относительные адреса лежат,которые преобразуются в абсолютные,либо заблинденные адреса,индексы,инные константы которые приаодятся к абсолютным адресам в рантайме но скорее не сохраняются в таблице
		3) адрес вычисляется из динамических велечин используя математическую формулу которая имеет логику вычисления последовательности N чисел для N битного радномного вектора
		4) каждый раз пораждается новые сигнатуры(опкоды реализации эвристики) или/и эвристика для вычисления адреса,меняются истосники пуоы энтропии(JIT)
	3) типы инструкции передачи управления:
		(0) аппаратные прерывания
		(1) программные прерывания
		(2) исключения в ходе рантайм исполнения инструкции(невалидная семантика контекста работы инструкции находящаяся на этапе конвеера execute/write-back).перехват исключения обработчиком
		(3) исключения в ходе стадии обработки конвеера fetch/decode(невалидная кодировка инструкции).перехват исключения обработчиком
		(4) безусловные инструкции передачи управления/ветвления
		(5) условные инструкции ветвления/передачи управления
	4) микроархитектурные баги изменяющие поведение fetch стадии конвеера микроархитектуры/семантики инструкций ветвлений
[8 ROP obfuscation]:
	1) mutation or unfolding && blinding runtime generate validate address
	2) opaque predicate generates condition goto RET insn
	3) возврат через генерацию исключения CFI и перехват обработчика ,который по таблице переходов либо в рантайме вычислит адрес перехода на return address
	4) ret2spec,микроархитектурные баги изменяющие поведение fetch стадии конвеера микроархитектуры/семантики инструкций ветвлений

[9 JIT obfuscation]:
	JIT obfuscation - компилятор в runtime пораждающий каждый раз новые сигнатуры,эвристику(обфусцированный код) для какого-то участка кода/блока/секции/сегмента/бинарника

	1) JIT native obfuscation - JIT obfuscation на уровне целевого кода(ЦВМ/ЭВМ)
	2) JIT VM1 ovfuscation - JIT obfuscation пораждающий обфусцировнный код для интерпретатора виртуальной машины (obfuscation Virtualization)
	3) JIT VMn obfuscation - JIT obfuscation пораждающий обфусцированный код для N вложенного интерпретатора (интерпретатор N который исполняет байткод(интерпретатор N+1) -> который исполняет байткод(интерпретатор N+2) -> который исполняет байткод(интерпретатор N+3) и.т.д.(интерпретатор реализованный или скомпилированный под байткод интерпретатора N-1:предыдущего или на уровне выше)

[10 VM obfuscation]:
	VM obfuscation - (самая сложная,муторная м бьющая по воемени обфускация) реализация интерпретатора(виртуального процессора) и статического бинарного транслятора/эмитера для интерпретатора VM

	интерпретатор имеет следующую конструкцию/скилет:

		preinit->init->fetch->decode->dispatch->handlers-\
			       ^---------------------------------/

	1) обфускация каждого этапа виртуалки
	2) динамическая кодировка битовых полей,опкодов инструкций/контекста VM:
		1) N инструкция определяет расположение опкодов, для инструкции N+1
		2) N инструкция определяет кодировку опкодов, для инструкции N+1
		3) комбинация 1,2 пунктов
		4) VM имеет N состояний - когда код делиться на N логических блоков контекста VM,где каждый контекст это состояние декодера(кодировка инструкций VM,набор инструкций);эвристика VM - то есть есть JIT обфускатор который при смене контекста виртуалки пораждает новую кодировку в рантайме ,набор инструкций для существующего байткода (то есть виртуалкк меняется подгоняя себя под новый байткод)
	
	скилет:

		entry:
			VMEnter VMContextN+1 ; entring to VM; select context VM:VMContextN+1
		VMContextN+1:
			; state encoding opcodes,bit fields for VMContextN+1
			; ISA for VMContextN+1
			bytecode for VMContextN+1
			; VSwitchContext insn(инструкция которая переключает контекст VM) or интерпретатор исполняет какое-то заданное количество N инструкций и меняет контекст,либо зависит от динамических events

		VMContextN+2:
			; new state encoding opcodes,bit fields for VMContextN+2			
			; ISA VM for VMContextN+2
			bytecode for VMContextN+2
			; VSwitchContext insn(инструкция которая переключает контекст VM) or интерпретатор исполняет какое-то заданное количество N инструкций и меняет контекст,либо зависит от динамических events

		VMContextN+3:
			; new state encoding opcodes,bit fields for VMContextN+3
                        ; ISA VM for VMContextN+3     
			bytecode for VMContextN+3 
			; VSwitchContext insn(инструкция которая переключает контекст VM) or интерпретатор исполняет какое-то заданное количество N инструкций и меняет контекст,либо зависит от динамических events
		
		VMContextN+4:
			; new state encoding opcodes,bit fields for VMContextN+4
                        ; ISA VM for VMContextN+4
			bytecode for VMContextN+4
			; VSwitchContext insn(инструкция которая переключает контекст VM) or интерпретатор исполняет какое-то заданное количество N инструкций и меняет контекст,либо зависит от динамических events

		VMContextN+M:
			; new state encoding opcodes,bit fields for VMContextN+M
                        ; ISA VM for VMContextN+M
			bytecode for VMContextN+M
			; VSwitchContext insn(инструкция которая переключает контекст VM) or интерпретатор исполняет какое-то заданное количество N инструкций и меняет контекст,либо зависит от динамических events
		
		5) код состоит из N байткодов,которые исполняют N интерпретаторов

		скилет: 
			// они не обязательно могут быть вместе,они могут быть разбросанны или размазанны виртуалки
			InterpreterVM+1
			{
			; ...
			}
			InterpreterVM+2
			{                                                                         ; ...
			}
			InterpreterVM+3
			{                                                                         ; ...
			}
			InterpreterVM+N
			{                                                                         ; ...
			}

		entry:
			VMEnter VM1_bytecode ; это нативный блок который передает аргументы виртуалки для инициализации и совершает переход по адресу где располагается VMEntry or VMPre-init or VMInit (зависит от виртуалки)
		VM1_bytecode:
			bytecode for InterpreterVM+1
			VMExit
			VMEnter VM2_bytecode
		VM2_bytecode:
			bytecode for InterpreterVM+2
			VMExit
			VMEnter VM3_bytecode
		VM3_bytecode:
			bytecode for InterpreterVM+3
			VMExit
			VMEnter VMn_bytecode
		VMn_bytecode:
			bytecode for InterpreterVM+N
			VMExit or VCall API(ExitProcess) or direct DKOM kernel api(Kill or ExitProcess) ; работа с кернел объектами возможна если есть ace в kernel thread or kernel callback function,который позволит через скрытый канал вызывать api

	6) InterpreterVM+1 исполняет InterpreterVM+2 реализованный для InterpreterVM+1,InterpreterVM+2 исполняет InterpreterVM+M реализованный для InterpreterVM+2 => InterpreterVM+M исполняет заданный семантически(алгоритм) байткод
	7) обфускация байткода
	8) использование JIT обфускатор(а/ов) для пораждения на каждом уровне виртуализации новые сигнатуры,эвристику

path learning: [1->2->3->4->5->6]
}

[SMT/SAT Solvers,symbex]:{
1) learning internal z3 solver
2) learning triton framework dse internal до сорцов включительно
3) рассмотреть angr
4) изучить др инструменты по symbex
5) практика crackmes,работенка
}

