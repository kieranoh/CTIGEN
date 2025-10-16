from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
import codecs
import sys
import os
def load_dotenv(path=".env"):
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, val = line.split("=", 1)
                os.environ.setdefault(key, val)
    except FileNotFoundError:
        pass

load_dotenv()

GHIDRA_HEADLESS_PATH = os.getenv("GHIDRA_HEADLESS_PATH")
GHIDRA_SCRIPT = os.getenv("GHIDRA_SCRIPT")
SAMPLE_EXE_PATH = os.getenv("SAMPLE_EXE_PATH")
SAMPLE_HASH = os.getenv("SAMPLE_HASH")
GHIDRA_OUTPUT_DIR = os.getenv("GHIDRA_OUTPUT_DIR")

program = currentProgram
decompinterface = DecompInterface()
decompinterface.openProgram(program)

binary_name = SAMPLE_HASH
output_dir = GHIDRA_OUTPUT_DIR
if not os.path.isdir(output_dir):
    os.makedirs(output_dir)
general_info_output_path = os.path.join(output_dir, binary_name + ".txt")

with codecs.open(general_info_output_path, "w", "utf-8") as general_info_file:
    
    general_info_file.write(u"[*] Binary Name: {}\n\n".format(currentProgram.getName()))

    functions = program.getFunctionManager().getFunctions(True)
    for function in list(functions):

        general_info_file.write(u"[*] Function Found: {}\n".format(function))
        general_info_file.write(u"    Address: {}\n".format(function.getEntryPoint()))

        try:
            decompile_result = decompinterface.decompileFunction(function, 0, ConsoleTaskMonitor())
            if not decompile_result.decompileCompleted():
                general_info_file.write(u"    Failed to decompile function\n\n")
                continue

            decompiled_function = decompile_result.getDecompiledFunction()
            decompiled_code = decompiled_function.getC()
            general_info_file.write(u"    Decompiled C Code:\n{}\n".format(decompiled_code))

            params = function.getParameters()
            for param in params:
                general_info_file.write(u"    Parameter: {} : {}\n".format(param.getName(), param.getDataType()))
            locals = function.getLocalVariables()
            for var in locals:
                general_info_file.write(u"    Local Variable: {} : {}\n".format(var.getName(), var.getDataType()))

            refMgr = currentProgram.getReferenceManager()
            references = refMgr.getReferencesTo(function.getEntryPoint())
            for ref in references:
                if ref.getReferenceType().isCall():
                    calling_function = program.getFunctionManager().getFunctionContaining(ref.getFromAddress())
                    if calling_function:
                        general_info_file.write(u"    Called by: {}\n".format(calling_function.getName()))

        except Exception as e:
            general_info_file.write(u"    Exception occurred: {}\n\n".format(e))

        general_info_file.write(u"\n")

print("Analysis completed. General function information is available in: " + general_info_output_path)