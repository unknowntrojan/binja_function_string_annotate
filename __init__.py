from typing import List
import binaryninja as bn
from binaryninja import BackgroundTaskThread
from binaryninja.binaryview import BinaryView, StringReference, DataVariable
from binaryninja.plugin import PluginCommand
from binaryninja.types import TypeClass, Type
from binaryninja.architecture import Architecture
from binaryninja.function import Function

class InspectInBackground(BackgroundTaskThread):    
    def __init__(self, bv: BinaryView):
        BackgroundTaskThread.__init__(
            self, "Annotating functions...", True)
        self.bv = bv

    def comment_at(self, addr: int, comment: str):
        original_comment = self.bv.get_comment_at(addr)
        
        original_comment = ''.join([line for line in original_comment.split('\n') if "REF: " not in line])
        
        if len(original_comment) > 0:
            original_comment += '\n'
            
        self.bv.set_comment_at(addr, original_comment + comment)

    def run(self):
        assert isinstance(self.bv.arch, Architecture)
        ptr_width = self.bv.arch.address_size
        
        # Dict<FuncAddr, &[String]>
        functions: dict[int, List[str]] = {}
        
        # for every string var, find all functions that reference it and tag them with the string
        for addr, var in self.bv.data_vars.items():
            if isinstance(var.type, Type):
                if var.type.type_class == TypeClass.ArrayTypeClass and "char" in var.type.get_string():
                    # is string
                    for ref in var.code_refs:
                        if isinstance(ref.function, Function):
                            if functions.get(ref.function.start) is None:
                                functions[ref.function.start] = []
                                    
                            functions[ref.function.start].append(str(var.value[:-1], 'utf-8').replace('\n', '\\n'))
        
        # for every function we just tagged with strings, annotate them and every reference to them
        for func_addr, strings in functions.items():
            if isinstance(strings, List):
                ref_string = f"REF: {', '.join(list(set(strings)))}"
                
                for ref in self.bv.get_code_refs(func_addr):
                    self.comment_at(ref.address, ref_string)
                    
                for addr in self.bv.get_data_refs(func_addr):
                    self.comment_at(addr, ref_string)
                
        self.bv.update_analysis_and_wait()

        print("finished annotating functions!")

def inspect(bv: BinaryView):
    if bv.analysis_info.state != 2:
        print(f'Binja analysis still ongoing, please run this plugin only after analysis completes.')
    else:
        background_thread = InspectInBackground(bv)
        background_thread.start()

PluginCommand.register("Annotate references to functions with strings used",
                          "Annotate references to functions with the strings that function references",
                          inspect)
