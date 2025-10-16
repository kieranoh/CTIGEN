# dump_instructions.py (Jython; JSONL streaming, no per-line flush)
from java.io import File, FileWriter, BufferedWriter
from ghidra.util.task import ConsoleTaskMonitor

def esc_json(s):
    sb = []
    for ch in s:
        o = ord(ch)
        if ch == '"' or ch == '\\':
            sb.append('\\' + ch)
        elif o < 0x20:
            sb.append('\\u%04x' % o)
        else:
            sb.append(ch)
    return ''.join(sb)

args = getScriptArgs()
out_path = args[0] if (args and len(args) > 0) else "out.jsonl"

prog = currentProgram
if prog is None:
    print("[dump_instructions] currentProgram is None -> skip")
    exit(0)

listing = prog.getListing()
fm = prog.getFunctionManager()
funcs = fm.getFunctions(True)

fobj = File(out_path)
parent = fobj.getParentFile()
if parent is not None and (not parent.exists()):
    parent.mkdirs()

bw = BufferedWriter(FileWriter(fobj, True))
monitor = ConsoleTaskMonitor()

try:
    while funcs.hasNext() and not monitor.isCancelled():
        func = funcs.next()
        body = func.getBody()
        it = listing.getInstructions(body, True)

        # JSONL: {"func_id":"name::addr","instrs":[ "...", "...", ... ]}
        bw.write('{"func_id":"')
        bw.write(esc_json(func.getName()))
        bw.write('::')
        bw.write(func.getEntryPoint().toString())
        bw.write('","instrs":[')

        first = True
        while it.hasNext():
            ins = it.next().toString()
            if first:
                first = False
            else:
                bw.write(',')
            bw.write('"')
            bw.write(esc_json(ins))
            bw.write('"')

        bw.write("]}\n")  
finally:
    try: bw.close()
    except: pass
