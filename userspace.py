# Copyright (c) 2012 Andrew White <awhite.au@gmail.com>

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or (at
# your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details. 
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA 
#

import json
import struct
import volatility.plugins.vadinfo as vadinfo
import volatility.plugins.taskmods as taskmods
import volatility.plugins.handles as handles
import volatility.obj as obj
import volatility.debug as debug
import volatility.constants as constants

class Userspace(handles.Handles, taskmods.DllList):
    """Explain the user allocations of a process"""

    def __init__(self, config, *args):
        handles.Handles.__init__(self, config, *args)
        taskmods.DllList.__init__(self, config, *args)


    def calculate(self):
        #check pid is valid before we spend time getting sections
        tasks = list(taskmods.DllList.calculate(self))
        pids = []
        for task in tasks:
            pids.append(int(task.UniqueProcessId))
        if not(int(self._config.PID) in pids):
            debug.error("Error - Invalid PID")

        #get handles for all processes by reseting the pid filter
        self.pid = self._config.PID
        self._config.PID = ""
        self.segments = self.get_section_segments()

        #revert pid option
        self._config.PID = self.pid

        #Check profile
        profile = self._config.profile
        if profile != "Win7SP1x86" and profile != "WinXPSP3x86":
            debug.warning("Warning - {0} profile not supported".format(self._config.profile))

        #analyze through each process
        for task in taskmods.DllList.calculate(self):
            for data in self.analyze(task):
                yield data


    def analyze(self, task):
        """Analyze the userspace memory and return allocation information"""
        pid = task.UniqueProcessId
        #get the process address space
        ps_ad = task.get_process_address_space()
        user_pages = self.get_user_pages(ps_ad)

        #get the user allocations
        self.user_allocs = {}
        self.unreferenced = []
        self.get_user_allocations(task, user_pages)

        #get the unreferenced KSHARED_USER_DATA
        self.get_kshared()

        #process kernel metadata
        self.get_kernel_metadata()

        #process user space metadata
        self.get_user_metadata(ps_ad, task, pid)

        #sort addresses for output purposes
        addresses = self.user_allocs.keys()
        addresses.sort()

        #return user allocation information
        yield task, self.user_allocs, addresses, self.unreferenced


    def render_text(self, outfd, data):
        """Print the results to the screen"""
        outfd.write("Acquiring Section Handles\n")        
        for task, user_allocs, addresses, unreferenced in data:
            #output process info
            info = "Analysing PID: {0:d} - {1:s}\n"
            pid = task.UniqueProcessId 
            outfd.write(info.format(pid, task.ImageFileName))

            #output user allocation information
            outfd.write("User Allocations\n")
            header = "{0:8} {1:8}  {2:8} {3:8}  {4:17}  {5:7}  {6}\n"
            outfd.write(header.format("Start", "End", "Used", "Size", "Permission", "Type", "Description"))
            outfd.write((("-"*8 + " ") * 2 + " ")*2 + "-"*17 + " "*2 + "-"*7 + " "*2 + "-"*35 + "\n")
            line = "{0:08x} {1:08x}  {2:08x} {3:08x}  {4:17s}  {5:8s} {6:s}"
            section = " "*66 + "{0}\n"
            for addr in addresses:
                alloc = user_allocs[addr]
                description = alloc.description()
                if description == "":
                    #output section info on same line
                    description = alloc.section_description
                    section_description = ""
                else:
                    #output section info on a different line
                    section_description = alloc.section_description                  
                outfd.write(line.format(alloc.start_address, 
                                        alloc.end_address, 
                                        alloc.allocated, 
                                        alloc.size, 
                                        alloc.permissions, 
                                        alloc.type,
                                        description + "\n"))

                if description != "" and section_description != "":
                    outfd.write(section.format(alloc.section_description))
            outfd.write("\n")

            #output any unreferenced pages
            outfd.write("Unreferenced Pages\n")
            outfd.write("Start\t Size\n")   
            for start, size in unreferenced:
                outfd.write("{0:08x} {1:08x}\n".format(start, size))
            outfd.write("\n")


    def render_json(self, outfd, data):
        """Return the results as json output"""

        out=dict(plugin_name="userspace",
                         tool_name="volatility",
                         tool_version=constants.VERSION)
        

        for task, user_allocs, addresses, unreferenced in data:
            process = {}
            process["pid"]={"value":str(task.UniqueProcessId)}
            process["name"]={"value":str(task.ImageFileName)}
            out["process"] = process
            out["user_allocations"] = []
            for addr in addresses:
                alloc = user_allocs[addr]
                entry = {}
                entry['start'] = {"value":"{0:08x}".format(alloc.start_address)}
                entry['end'] = {"value":"{0:08x}".format(alloc.end_address)}
                entry['allocated'] = {"value":"{0:08x}".format(alloc.allocated)}
                entry['size'] = {"value":"{0:08x}".format(alloc.size)}
                entry['permissions'] = {"value":str(alloc.permissions)}
                entry['type'] = {"value":str(alloc.type)}
                entry['description'] = {"value":str(alloc.description())}
                entry['section'] = {"value":str(alloc.section_description)}
                out["user_allocations"].append(entry)
            out["unreferenced"] = []
            for start, size in unreferenced:
                unref = {}
                unref['start'] = {"value":str(start)}
                unref['size'] = {"value":str(size)}
                out["unreferenced"].append(unref)

            outfd.write(json.dumps(out,indent=4))

    def get_section_segments(self):
        """Parse the object manager for segments of section objects"""
        segments = {}
        self._config.OBJECT_TYPE = "Section"
        obj_handles = handles.Handles.calculate(self)
        for pid, h, otype, name in obj_handles:
            #Get the segment pointed to by the segment field of a section 
            #object. Although the type is supposedly a _SEGMENT_OBJECT, 
            #it is in fact a _SEGMENT instead. We use these _SEGMENTS to
            #link the section to a user allocation
            section_obj = obj.Object("_SECTION_OBJECT", h.Body.obj_offset, h.obj_vm)    
            segment_addr = section_obj.Segment.v()
            segment = obj.Object("_SEGMENT", segment_addr, h.obj_vm)
            segments[segment_addr] = [pid, name, segment]
            #Note - Vol 2.1 removes the "gibberish" section names
            #containing non-ascii characters
        return segments


    def get_user_pages(self, ps_ad):
        """Return a list of all accessible userspace virtual address pages"""
        all_pages = ps_ad.get_available_pages()
        pages = []
        for page in all_pages:
            if page[0] < 0x80000000: 
                #not always a valid assumption (eg 3GB switch)
                pages.append(page)
        return pages


    def get_user_allocations(self, task, user_pages):
        """Traverse the VAD and get the user allocations and locate
            any unreferenced memory pages"""
        for vad in task.VadRoot.traverse():
            alloc = Userspace.UserAlloc(vad)
            user_pages = alloc.pages_allocated(user_pages)
            self.user_allocs[alloc.start_address] = alloc
        self.unreferenced = user_pages


    def get_kshared(self):
        """Find the _KSHARED_USER_DATA structure @ 7FFE0000"""
        pages = []
        for [start, size] in self.unreferenced:
            if start == 0x7FFE0000:
                alloc = Userspace.UserAlloc(None, start, size, 
                                            "KSHARED_USER_DATA")
                self.user_allocs[start] = alloc
            else:
                pages.append([start, size])
        self.unreferenced = pages


    def get_kernel_metadata(self):
        """Get file object and section object metadata"""
        self.get_files()
        self.get_sections()


    def get_files(self):
        """Check each VAD for a file object"""
        for alloc in self.user_allocs.values():
            if alloc.vad:
                file_object = None
                try:
                    file_object = alloc.vad.FileObject
                except:
                    continue
                if file_object and file_object.is_valid():
                    filename = str(file_object.FileName)
                    if filename != "":
                        alloc.add_file(filename)
        

    def get_sections(self):
        """Link each section to a user allocation"""
        for alloc in self.user_allocs.values():
            if alloc.vad:
                control_area = None
                try:
                    control_area = alloc.vad.ControlArea
                except:
                    pass
                if not control_area:
                    continue
                if not control_area.is_valid():
                    continue
                if control_area.v() != control_area.Segment.ControlArea.v():    
                    #invalid control area
                    continue
                #Control Area indicates the allocation is mapped
                alloc.type = "Mapped"
                #check if the segment matches the segment from a section
                addr = control_area.Segment.v()
                if addr == 0:
                    continue
                if addr in self.segments:
                    pid, name, segment = self.segments[addr]
                    text = "Section - PID {0:05}, Name {1}".format(pid, name)
                    alloc.add_section(text)

        
    def get_user_metadata(self, ps_ad, task, pid):
        """Get the metadata from the userspace"""
        #Process Environment Block
        peb = task.Peb
        self.user_allocs[peb.v()].add_metadata("PEB")
        #Data from PEB
        gdi_handles, size = self.get_peb_data(peb)
        #Scan handle table for possible allocations
        if gdi_handles:
            self.get_gdi_data(ps_ad, gdi_handles, size, pid)
        #Heaps and related heap metadata
        self.get_heaps(ps_ad, peb)
        #Thread Environment Block and Stacks
        pcb = task.Pcb
        tebs = self.get_tebs(ps_ad, pcb)
        #Track the thread number
        count = 0
        for teb in tebs:
            self.get_stack(teb, count)
            count += 1


    def get_peb_data(self, peb):
        """Get the metadata from the PEB"""
        fields = ["ProcessParameters", "AnsiCodePageData",
                  "SystemDefaultActivationContextData", "ActivationContextData",
                  "GdiSharedHandleTable", "pShimData", "pContextData",
                  "WerRegistrationData"]

        gdi = 0
        size = 0
        for field in fields:
            try:
                data = peb.m(field)
                addr = data.v()
                if addr == 0:
                    continue
                if not(addr in self.user_allocs):
                    #pointer is inside allocation rather than to start?
                    warning = "Pointer into allocation {0} @ {1:08x}"
                    debug.Warning(warning.format(field, addr))
                    continue
                #field specific information
                if field == "GdiSharedHandleTable":
                    #save for individual analysis
                    gdi = addr
                    size = self.user_allocs[addr].size
                elif field == "AnsiCodePageData":
                    #rename this field in output
                    field = "CodePage"
                elif field == "ProcessParameters":
                    #get the environment
                    environment = data.Environment.v()
                    self.user_allocs[environment].add_metadata("Environment")
                #add the metadata to the user alloc
                self.user_allocs[addr].add_metadata(field)
            except:
                continue
        return gdi, size


    def get_heaps(self, ps_ad, peb):
        """Get the heaps and heap related data structures"""
        num_heaps = peb.NumberOfHeaps.v()
        heap_count = 0
        heaps = obj.Object('Array', offset = peb.ProcessHeaps.v(),
                                vm = ps_ad, targetType = 'unsigned long', 
                                count = num_heaps)
        heaps_list = list(heaps)

        #add shared heap to list
        heaps_list.append(peb.ReadOnlySharedMemoryBase)

        #process each heap for metadata
        data = []
        for address in heaps_list:
            if heap_count == len(heaps_list) - 1:
                #shared heap
                heap_info = str(heap_count) + " (Shared)"
            else:
                heap_info = str(heap_count)
            #add heap
            heap = obj.Object('_HEAP', offset = address.v(), vm = ps_ad)
            if not(heap.is_valid()):
                debug.warning("Unreadable heap @ {0:08x}".format(address.v()))
                heap_text = "Heap {0} (Unreadable)".format(heap_info)
                data.append([address.v(), heap_text])
                heap_count += 1
                continue
            data.append([address.v(), "Heap {0}".format(heap_info)])
            #parse for heap virtual allocs
            for virtual_alloc in self.get_heap_virtual_allocs(ps_ad, heap, 
                                                              heap_info):
                data.append(virtual_alloc)
            #parse for heap segments
            for segment in self.get_heap_segments(ps_ad, heap, heap_info):
                data.append(segment)
            heap_count += 1

        #add heap data to user allocs
        for addr, text in data:
            self.user_allocs[addr].add_metadata(text)


    def get_heap_virtual_allocs(self, ps_ad, heap, heap_info):
        """Get the heap virtual alloc entries of the heap"""
        #finding _HEAP_VIRTUAL_ALLOC objects
        va_count = 0
        start = heap.VirtualAllocdBlocks.v()
        va_text = "Virtual Alloc {0} of Heap {1}"
        for offset in self.follow_list_entry(ps_ad, start, "Virtual Alloc"):
            yield [offset, va_text.format(va_count, heap_info)]
            va_count += 1
        

    def follow_list_entry(self, ps_ad, offset, name):
        """Traverse a _LIST_ENTRY and yield all object offsets"""
        head = obj.Object('_LIST_ENTRY', offset=offset, vm=ps_ad)
        if not(head.is_valid()):
            warning = "Invalid {0} head @ {1:08x}"
            debug.warning(warning).format(name, head.v())
            return
        current = obj.Object('_LIST_ENTRY', offset=head.Flink.v(), vm=ps_ad)
        previous = head
        while current.v() != head.v():
            if current.Blink.v() != previous.v():
                #invalid
                warning = "Invalid {0} flink in list @ {1:08x}"
                debug.warning(warning).format(name, previous.v())
                return
            yield current.v()
            current = obj.Object('_LIST_ENTRY', offset=current.Flink.v(), 
                                                vm=ps_ad)
            previous = obj.Object('_LIST_ENTRY', offset=current.Blink.v(), 
                                                 vm=ps_ad)

    def get_heap_segments(self, ps_ad, heap, heap_info):
        """Get the segments of the heap"""
        #finding _HEAP_SEGMENT objects
        if ps_ad.profile.obj_has_member("_HEAP", "Segments"):
            #WinXP stores segments in a fixed sized array
            for segment in self.get_heap_segments_array(ps_ad, heap, heap_info):
                yield segment
        elif ps_ad.profile.obj_has_member("_HEAP", "SegmentListEntry"):
            #Win7 stores segments in a linked list
            for segment in self.get_heap_segments_list(ps_ad, heap, heap_info):
                yield segment
            

    def get_heap_segments_array(self, ps_ad, heap, heap_info):
        """Get the heap segments from _HEAP.Segments"""
        seg_count = 0
        seg_text = "Segment {0} of Heap {1}"
        for segment in heap.Segments:
            if segment != 0 and seg_count != 0:
                #skip first segment as it will be within the original heap
                text = seg_text.format(seg_count, heap_info)
                yield [segment.v(), text]
            seg_count += 1


    def get_heap_segments_list(self, ps_ad, heap, heap_info):
        """Get the heap segments from _HEAP.SegmentListEntry"""
        seg_count = 0
        seg_text = "Segment {0} of Heap {1}"
        start = heap.SegmentListEntry.v()
        field_offset = ps_ad.profile.get_obj_offset("_HEAP_SEGMENT", 
                                                    "SegmentListEntry")
        seg_text = "Segment {0} of Heap {1}"
        for offset in self.follow_list_entry(ps_ad, start, "Heap Segment"):
            #ignore internal segments, which will be in the original heap
            if (offset - field_offset) % 0x1000 == 0:
                text = seg_text.format(seg_count, heap_info)
                yield [offset - field_offset, text]
            seg_count += 1

    def get_gdi_data(self, ps_ad, gdi_handles, size, pid):
        """Look any allocations containing GDI objects by parsing
            gdi handle table"""
        #Parsing GDIHandleEntry objects
        #see http://msdn.microsoft.com/en-au/magazine/cc188782.aspx
        pointers = []
        current = gdi_handles + 0x4
        while current < gdi_handles + size:
            if ps_ad.is_valid_address(current):
                #read PID
                gdi_pid = ps_ad.read(current, 2)
                gdi_pid = struct.unpack("<H", gdi_pid)[0]                    
                if gdi_pid != pid:
                    current += 0x10
                    continue
                current += 0x8
                #read object address
                value = ps_ad.read(current, 4)
                value = struct.unpack("<L", value)[0]
                if value >= 0:
                    pointers.append(value)
                current += 0x8
            else:
                current += 0x1000
        #check if these objects are in user allocations    
        for pointer in pointers:
            for alloc in self.user_allocs.values():
                if alloc.start_address <= pointer < alloc.end_address:
                    alloc.add_gdi("(GDI Data)")
        

    def get_tebs(self, ps_ad, pcb):
        """Get the Thread Execution Blocks of the process"""
        tebs = []
        count = 0
        
        #get offset of ThreadListEntry, should be 0x1b0 on XP and 0x1e0 on Win7
        field_offset = ps_ad.profile.get_obj_offset("_KTHREAD", "ThreadListEntry")

        #get the threads
        for offset in self.follow_list_entry(ps_ad, pcb.ThreadListHead.v(), "Thread"):
            kthread = obj.Object('_KTHREAD', offset = offset - field_offset,
                                             vm = ps_ad)
            teb = kthread.Teb.dereference_as("_TEB")
            teb_addr = kthread.Teb.v()

            #check if it has been paged out
            if teb.is_valid():
                text = "TEB (Thread {0})".format(count)
            else:
                text = "TEB (Thread {0}) (unreadable)".format(count)
            
            tebs.append(teb)
            #add to the user allocation
            self.user_allocs[teb_addr].add_metadata(text)
            count += 1

        return tebs


    def get_stack(self, teb, count):
        """Get the stack of the thread"""
        #check for TEBs that have been paged out
        #although this seems illogical, it can happen
        if not(teb.is_valid()):
            return
        stack_max = teb.DeallocationStack.v()
        text = "Stack of Thread {0}".format(count)
        self.user_allocs[stack_max].add_metadata(text)


    class UserAlloc(object):
        """Class to describe a user allocation"""
        
        def __init__(self, vad, start_address=None, size=None, description=None):
            if vad:
                #For user allocations with a VAD (most allocations)
                self.vad = vad
                self.start_address = vad.Start
                self.end_address = vad.End
                self.permissions = self.get_permissions(vad)
                self.size = self.end_address - self.start_address + 1
                self.internal_description = ""
                tag = vad.Tag
                self.allocated = 0
                if tag == "Vad ":
                    #This type of VAD is always mapped
                    self.type = "VMapped"
                else:
                    self.type = "Private"
            else:
                #For allocations without a VAD, eg KSHARED_USER_DATA
                self.vad = None
                self.start_address = start_address
                self.end_address = start_address + size - 1
                self.internal_description = description
                self.size = size
                #set allocated manually since it is described by the VAD
                #and it must be this size else it would have not been located
                self.allocated = size
                self.type = "N/A"
                self.permissions = "N/A"     
            self.section_description = ""
            self.gdi_description = ""


        def description(self):
            """Return a string that describes this allocation"""
            description = self.internal_description
            if self.gdi_description != "":
                description += " " + self.gdi_description
            description = description.strip()
            return description


        def get_permissions(self, vad):
            """Get the permissions of this user allocation"""
            permissions = vad.u.VadFlags.Protection.v()
            try:
                permissions = vadinfo.PROTECT_FLAGS[permissions]
                #remove unnecessary text to compress output
                permissions = permissions.replace("PAGE_", "")
                return permissions
            except IndexError:
                return "Unknown - {0:x}".format(permissions)


        def pages_allocated(self, user_pages):
           """Determine how much of an allocation is actually accessible"""
           # operates on individual page information (not ranges)
           # returns unused pages separately to speed future searches
           allocated = 0
           unused = []
           for start, size in user_pages:
               if start >= self.start_address and start <= self.end_address:
                   allocated += size
               else:
                   unused.append([start,size])
           self.allocated = allocated       
           return unused            


        def add_section(self, text):
            """Add section metadata separately, as a user allocation 
            can potentially have section and content info (eg shared heap)"""
            self.section_description = text


        def add_file(self, text):
            """Add file information"""
            self.add_metadata(text)


        def add_metadata(self, text):
            """Add information about the contents of this user allocation"""
            self.internal_description = text 


        def add_gdi(self, text):
            """GDI objects found in this user allocation"""
            self.gdi_description = text

