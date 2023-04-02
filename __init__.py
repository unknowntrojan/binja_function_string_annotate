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
            self, "Annotating functions in vTables...", True)
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
        
        # Dictionary of all functions contained in vTables
        # Dict<FuncAddr, &[EntryAddrToComment]>
        functions = {}
        
        # Dict<CommentAddr, [Comment]>
        comments = {}
        
        for addr, var in self.bv.data_vars.items():
            if isinstance(var.name, str):
                if "::vfTable" in var.name:
                    # find all functions referenced by the vTable
                    if isinstance(var.value, List):
                        # get the entry datavar
                        for i, value in enumerate(var.value):
                                # get the function it points to
                                func = self.bv.get_function_at(value)
                                
                                if isinstance(func, Function):
                                    if functions.get(func.start) is None:
                                        functions[func.start] = []
                                    
                                    functions[func.start].append(addr + i * ptr_width)     
                                    
        for addr, var in self.bv.data_vars.items():                                       
            if isinstance(var.type, Type):
                # find every string that has code refs in our functions
                typ = var.type
                # if this datavar is a string
                if (typ.type_class == TypeClass.ArrayTypeClass or typ.type_class == TypeClass.PointerTypeClass) and "char" in typ.get_string():
                    # if this string is referenced by one of our functions
                    for ref in var.code_refs:
                        func = ref.function
                        if isinstance(func, Function):
                            if func.start in functions:
                                for comment_addr in functions[func.start]:
                                    if comments.get(comment_addr) is None:
                                        comments[comment_addr] = []
                                    
                                    value = ""
                                    
                                    if typ.type_class == TypeClass.ArrayTypeClass:
                                        value = str(var.value[:-1], 'utf-8').replace('\n', '\\n')
                                    elif typ.type_class == TypeClass.PointerTypeClass:
                                        value = self.bv.get_string_at(var.value)
                                
                                    value = f"\"{value}\""
                                    
                                    comments[comment_addr].append(value)
        
        for addr, comment in comments.items():
            if isinstance(comment, List):
                ref_string = f"REF: {', '.join(list(set(comment)))}"
               
                print(f"setting comment at {hex(addr)}")
                self.comment_at(addr, ref_string)
                
                data_var = self.bv.get_data_var_at(addr)
                if isinstance(data_var, DataVariable):
                    self.comment_at(data_var.value, ref_string)
                
        self.bv.update_analysis_and_wait()

        print("finished annotating functions!")

def inspect(bv: BinaryView):
    if bv.analysis_info.state != 2:
        print(f'Binja analysis still ongoing, please run this plugin only after analysis completes.')
    else:
        background_thread = InspectInBackground(bv)
        background_thread.start()

PluginCommand.register("Annotate Functions in vTables with Strings",
                          "Annotate vTables with what strings the functions use",
                          inspect)
