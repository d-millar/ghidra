/* ###
 * IP: Apache License 2.0 with LLVM Exceptions
 */
package SWIG;


/* ----------------------------------------------------------------------------
 * This file was automatically generated by SWIG (http://www.swig.org).
 * Version 4.0.2
 *
 * Do not make changes to this file unless you know what you are doing--modify
 * the SWIG interface file instead.
 * ----------------------------------------------------------------------------- */


public class SBTarget {
  private transient long swigCPtr;
  protected transient boolean swigCMemOwn;

  protected SBTarget(long cPtr, boolean cMemoryOwn) {
    swigCMemOwn = cMemoryOwn;
    swigCPtr = cPtr;
  }

  protected static long getCPtr(SBTarget obj) {
    return (obj == null) ? 0 : obj.swigCPtr;
  }

  @SuppressWarnings("deprecation")
  protected void finalize() {
    delete();
  }

  public synchronized void delete() {
    if (swigCPtr != 0) {
      if (swigCMemOwn) {
        swigCMemOwn = false;
        lldbJNI.delete_SBTarget(swigCPtr);
      }
      swigCPtr = 0;
    }
  }

  public SBTarget() {
    this(lldbJNI.new_SBTarget__SWIG_0(), true);
  }

  public SBTarget(SBTarget rhs) {
    this(lldbJNI.new_SBTarget__SWIG_1(SBTarget.getCPtr(rhs), rhs), true);
  }

  public static String GetBroadcasterClassName() {
    return lldbJNI.SBTarget_GetBroadcasterClassName();
  }

  public boolean IsValid() {
    return lldbJNI.SBTarget_IsValid(swigCPtr, this);
  }

  public static boolean EventIsTargetEvent(SBEvent event) {
    return lldbJNI.SBTarget_EventIsTargetEvent(SBEvent.getCPtr(event), event);
  }

  public static SBTarget GetTargetFromEvent(SBEvent event) {
    return new SBTarget(lldbJNI.SBTarget_GetTargetFromEvent(SBEvent.getCPtr(event), event), true);
  }

  public static long GetNumModulesFromEvent(SBEvent event) {
    return lldbJNI.SBTarget_GetNumModulesFromEvent(SBEvent.getCPtr(event), event);
  }

  public static SBModule GetModuleAtIndexFromEvent(long idx, SBEvent event) {
    return new SBModule(lldbJNI.SBTarget_GetModuleAtIndexFromEvent(idx, SBEvent.getCPtr(event), event), true);
  }

  public SBProcess GetProcess() {
    return new SBProcess(lldbJNI.SBTarget_GetProcess(swigCPtr, this), true);
  }

  public SBPlatform GetPlatform() {
    return new SBPlatform(lldbJNI.SBTarget_GetPlatform(swigCPtr, this), true);
  }

  public SBError Install() {
    return new SBError(lldbJNI.SBTarget_Install(swigCPtr, this), true);
  }

  public SBProcess Launch(SBListener listener, SWIGTYPE_p_p_char argv, SWIGTYPE_p_p_char envp, String stdin_path, String stdout_path, String stderr_path, String working_directory, long launch_flags, boolean stop_at_entry, SBError error) {
    return new SBProcess(lldbJNI.SBTarget_Launch__SWIG_0(swigCPtr, this, SBListener.getCPtr(listener), listener, SWIGTYPE_p_p_char.getCPtr(argv), SWIGTYPE_p_p_char.getCPtr(envp), stdin_path, stdout_path, stderr_path, working_directory, launch_flags, stop_at_entry, SBError.getCPtr(error), error), true);
  }

  public SBProcess LaunchSimple(SWIGTYPE_p_p_char argv, SWIGTYPE_p_p_char envp, String working_directory) {
    return new SBProcess(lldbJNI.SBTarget_LaunchSimple(swigCPtr, this, SWIGTYPE_p_p_char.getCPtr(argv), SWIGTYPE_p_p_char.getCPtr(envp), working_directory), true);
  }

  public SBProcess Launch(SBLaunchInfo launch_info, SBError error) {
    return new SBProcess(lldbJNI.SBTarget_Launch__SWIG_1(swigCPtr, this, SBLaunchInfo.getCPtr(launch_info), launch_info, SBError.getCPtr(error), error), true);
  }

  public SBProcess LoadCore(String core_file) {
    return new SBProcess(lldbJNI.SBTarget_LoadCore__SWIG_0(swigCPtr, this, core_file), true);
  }

  public SBProcess LoadCore(String core_file, SBError error) {
    return new SBProcess(lldbJNI.SBTarget_LoadCore__SWIG_1(swigCPtr, this, core_file, SBError.getCPtr(error), error), true);
  }

  public SBProcess Attach(SBAttachInfo attach_info, SBError error) {
    return new SBProcess(lldbJNI.SBTarget_Attach(swigCPtr, this, SBAttachInfo.getCPtr(attach_info), attach_info, SBError.getCPtr(error), error), true);
  }

  public SBProcess AttachToProcessWithID(SBListener listener, java.math.BigInteger pid, SBError error) {
    return new SBProcess(lldbJNI.SBTarget_AttachToProcessWithID(swigCPtr, this, SBListener.getCPtr(listener), listener, pid, SBError.getCPtr(error), error), true);
  }

  public SBProcess AttachToProcessWithName(SBListener listener, String name, boolean wait_for, SBError error) {
    return new SBProcess(lldbJNI.SBTarget_AttachToProcessWithName(swigCPtr, this, SBListener.getCPtr(listener), listener, name, wait_for, SBError.getCPtr(error), error), true);
  }

  public SBProcess ConnectRemote(SBListener listener, String url, String plugin_name, SBError error) {
    return new SBProcess(lldbJNI.SBTarget_ConnectRemote(swigCPtr, this, SBListener.getCPtr(listener), listener, url, plugin_name, SBError.getCPtr(error), error), true);
  }

  public SBFileSpec GetExecutable() {
    return new SBFileSpec(lldbJNI.SBTarget_GetExecutable(swigCPtr, this), true);
  }

  public void AppendImageSearchPath(String from, String to, SBError error) {
    lldbJNI.SBTarget_AppendImageSearchPath(swigCPtr, this, from, to, SBError.getCPtr(error), error);
  }

  public boolean AddModule(SBModule module) {
    return lldbJNI.SBTarget_AddModule__SWIG_0(swigCPtr, this, SBModule.getCPtr(module), module);
  }

  public SBModule AddModule(String path, String triple, String uuid) {
    return new SBModule(lldbJNI.SBTarget_AddModule__SWIG_1(swigCPtr, this, path, triple, uuid), true);
  }

  public SBModule AddModule(String path, String triple, String uuid_cstr, String symfile) {
    return new SBModule(lldbJNI.SBTarget_AddModule__SWIG_2(swigCPtr, this, path, triple, uuid_cstr, symfile), true);
  }

  public SBModule AddModule(SBModuleSpec module_spec) {
    return new SBModule(lldbJNI.SBTarget_AddModule__SWIG_3(swigCPtr, this, SBModuleSpec.getCPtr(module_spec), module_spec), true);
  }

  public long GetNumModules() {
    return lldbJNI.SBTarget_GetNumModules(swigCPtr, this);
  }

  public SBModule GetModuleAtIndex(long idx) {
    return new SBModule(lldbJNI.SBTarget_GetModuleAtIndex(swigCPtr, this, idx), true);
  }

  public boolean RemoveModule(SBModule module) {
    return lldbJNI.SBTarget_RemoveModule(swigCPtr, this, SBModule.getCPtr(module), module);
  }

  public SBDebugger GetDebugger() {
    return new SBDebugger(lldbJNI.SBTarget_GetDebugger(swigCPtr, this), true);
  }

  public SBModule FindModule(SBFileSpec file_spec) {
    return new SBModule(lldbJNI.SBTarget_FindModule(swigCPtr, this, SBFileSpec.getCPtr(file_spec), file_spec), true);
  }

  public SBSymbolContextList FindCompileUnits(SBFileSpec sb_file_spec) {
    return new SBSymbolContextList(lldbJNI.SBTarget_FindCompileUnits(swigCPtr, this, SBFileSpec.getCPtr(sb_file_spec), sb_file_spec), true);
  }

  public ByteOrder GetByteOrder() {
    return ByteOrder.swigToEnum(lldbJNI.SBTarget_GetByteOrder(swigCPtr, this));
  }

  public long GetAddressByteSize() {
    return lldbJNI.SBTarget_GetAddressByteSize(swigCPtr, this);
  }

  public String GetTriple() {
    return lldbJNI.SBTarget_GetTriple(swigCPtr, this);
  }

  public long GetDataByteSize() {
    return lldbJNI.SBTarget_GetDataByteSize(swigCPtr, this);
  }

  public long GetCodeByteSize() {
    return lldbJNI.SBTarget_GetCodeByteSize(swigCPtr, this);
  }

  public SBError SetSectionLoadAddress(SBSection section, java.math.BigInteger section_base_addr) {
    return new SBError(lldbJNI.SBTarget_SetSectionLoadAddress(swigCPtr, this, SBSection.getCPtr(section), section, section_base_addr), true);
  }

  public SBError ClearSectionLoadAddress(SBSection section) {
    return new SBError(lldbJNI.SBTarget_ClearSectionLoadAddress(swigCPtr, this, SBSection.getCPtr(section), section), true);
  }

  public SBError SetModuleLoadAddress(SBModule module, long sections_offset) {
    return new SBError(lldbJNI.SBTarget_SetModuleLoadAddress(swigCPtr, this, SBModule.getCPtr(module), module, sections_offset), true);
  }

  public SBError ClearModuleLoadAddress(SBModule module) {
    return new SBError(lldbJNI.SBTarget_ClearModuleLoadAddress(swigCPtr, this, SBModule.getCPtr(module), module), true);
  }

  public SBSymbolContextList FindFunctions(String name, long name_type_mask) {
    return new SBSymbolContextList(lldbJNI.SBTarget_FindFunctions__SWIG_0(swigCPtr, this, name, name_type_mask), true);
  }

  public SBSymbolContextList FindFunctions(String name) {
    return new SBSymbolContextList(lldbJNI.SBTarget_FindFunctions__SWIG_1(swigCPtr, this, name), true);
  }

  public SBType FindFirstType(String type) {
    return new SBType(lldbJNI.SBTarget_FindFirstType(swigCPtr, this, type), true);
  }

  public SBTypeList FindTypes(String type) {
    return new SBTypeList(lldbJNI.SBTarget_FindTypes(swigCPtr, this, type), true);
  }

  public SBType GetBasicType(BasicType type) {
    return new SBType(lldbJNI.SBTarget_GetBasicType(swigCPtr, this, type.swigValue()), true);
  }

  public SBSourceManager GetSourceManager() {
    return new SBSourceManager(lldbJNI.SBTarget_GetSourceManager(swigCPtr, this), true);
  }

  public SBValueList FindGlobalVariables(String name, long max_matches) {
    return new SBValueList(lldbJNI.SBTarget_FindGlobalVariables__SWIG_0(swigCPtr, this, name, max_matches), true);
  }

  public SBValue FindFirstGlobalVariable(String name) {
    return new SBValue(lldbJNI.SBTarget_FindFirstGlobalVariable(swigCPtr, this, name), true);
  }

  public SBValueList FindGlobalVariables(String name, long max_matches, MatchType matchtype) {
    return new SBValueList(lldbJNI.SBTarget_FindGlobalVariables__SWIG_1(swigCPtr, this, name, max_matches, matchtype.swigValue()), true);
  }

  public SBSymbolContextList FindGlobalFunctions(String name, long max_matches, MatchType matchtype) {
    return new SBSymbolContextList(lldbJNI.SBTarget_FindGlobalFunctions(swigCPtr, this, name, max_matches, matchtype.swigValue()), true);
  }

  public void Clear() {
    lldbJNI.SBTarget_Clear(swigCPtr, this);
  }

  public SBAddress ResolveFileAddress(java.math.BigInteger file_addr) {
    return new SBAddress(lldbJNI.SBTarget_ResolveFileAddress(swigCPtr, this, file_addr), true);
  }

  public SBAddress ResolveLoadAddress(java.math.BigInteger vm_addr) {
    return new SBAddress(lldbJNI.SBTarget_ResolveLoadAddress(swigCPtr, this, vm_addr), true);
  }

  public SBAddress ResolvePastLoadAddress(long stop_id, java.math.BigInteger vm_addr) {
    return new SBAddress(lldbJNI.SBTarget_ResolvePastLoadAddress(swigCPtr, this, stop_id, vm_addr), true);
  }

  public SBSymbolContext ResolveSymbolContextForAddress(SBAddress addr, long resolve_scope) {
    return new SBSymbolContext(lldbJNI.SBTarget_ResolveSymbolContextForAddress(swigCPtr, this, SBAddress.getCPtr(addr), addr, resolve_scope), true);
  }

  public long ReadMemory(SBAddress addr, SWIGTYPE_p_void buf, long size, SBError error) {
    return lldbJNI.SBTarget_ReadMemory(swigCPtr, this, SBAddress.getCPtr(addr), addr, SWIGTYPE_p_void.getCPtr(buf), size, SBError.getCPtr(error), error);
  }

  public SBBreakpoint BreakpointCreateByLocation(String file, long line) {
    return new SBBreakpoint(lldbJNI.SBTarget_BreakpointCreateByLocation__SWIG_0(swigCPtr, this, file, line), true);
  }

  public SBBreakpoint BreakpointCreateByLocation(SBFileSpec file_spec, long line) {
    return new SBBreakpoint(lldbJNI.SBTarget_BreakpointCreateByLocation__SWIG_1(swigCPtr, this, SBFileSpec.getCPtr(file_spec), file_spec, line), true);
  }

  public SBBreakpoint BreakpointCreateByLocation(SBFileSpec file_spec, long line, java.math.BigInteger offset) {
    return new SBBreakpoint(lldbJNI.SBTarget_BreakpointCreateByLocation__SWIG_2(swigCPtr, this, SBFileSpec.getCPtr(file_spec), file_spec, line, offset), true);
  }

  public SBBreakpoint BreakpointCreateByLocation(SBFileSpec file_spec, long line, java.math.BigInteger offset, SBFileSpecList module_list) {
    return new SBBreakpoint(lldbJNI.SBTarget_BreakpointCreateByLocation__SWIG_3(swigCPtr, this, SBFileSpec.getCPtr(file_spec), file_spec, line, offset, SBFileSpecList.getCPtr(module_list), module_list), true);
  }

  public SBBreakpoint BreakpointCreateByLocation(SBFileSpec file_spec, long line, long column, java.math.BigInteger offset, SBFileSpecList module_list) {
    return new SBBreakpoint(lldbJNI.SBTarget_BreakpointCreateByLocation__SWIG_4(swigCPtr, this, SBFileSpec.getCPtr(file_spec), file_spec, line, column, offset, SBFileSpecList.getCPtr(module_list), module_list), true);
  }

  public SBBreakpoint BreakpointCreateByLocation(SBFileSpec file_spec, long line, long column, java.math.BigInteger offset, SBFileSpecList module_list, boolean move_to_nearest_code) {
    return new SBBreakpoint(lldbJNI.SBTarget_BreakpointCreateByLocation__SWIG_5(swigCPtr, this, SBFileSpec.getCPtr(file_spec), file_spec, line, column, offset, SBFileSpecList.getCPtr(module_list), module_list, move_to_nearest_code), true);
  }

  public SBBreakpoint BreakpointCreateByName(String symbol_name, String module_name) {
    return new SBBreakpoint(lldbJNI.SBTarget_BreakpointCreateByName__SWIG_0(swigCPtr, this, symbol_name, module_name), true);
  }

  public SBBreakpoint BreakpointCreateByName(String symbol_name) {
    return new SBBreakpoint(lldbJNI.SBTarget_BreakpointCreateByName__SWIG_1(swigCPtr, this, symbol_name), true);
  }

  public SBBreakpoint BreakpointCreateByName(String symbol_name, long func_name_type, SBFileSpecList module_list, SBFileSpecList comp_unit_list) {
    return new SBBreakpoint(lldbJNI.SBTarget_BreakpointCreateByName__SWIG_2(swigCPtr, this, symbol_name, func_name_type, SBFileSpecList.getCPtr(module_list), module_list, SBFileSpecList.getCPtr(comp_unit_list), comp_unit_list), true);
  }

  public SBBreakpoint BreakpointCreateByName(String symbol_name, long func_name_type, LanguageType symbol_language, SBFileSpecList module_list, SBFileSpecList comp_unit_list) {
    return new SBBreakpoint(lldbJNI.SBTarget_BreakpointCreateByName__SWIG_3(swigCPtr, this, symbol_name, func_name_type, symbol_language.swigValue(), SBFileSpecList.getCPtr(module_list), module_list, SBFileSpecList.getCPtr(comp_unit_list), comp_unit_list), true);
  }

  public SBBreakpoint BreakpointCreateByNames(SWIGTYPE_p_p_char symbol_name, long num_names, long name_type_mask, SBFileSpecList module_list, SBFileSpecList comp_unit_list) {
    return new SBBreakpoint(lldbJNI.SBTarget_BreakpointCreateByNames__SWIG_0(swigCPtr, this, SWIGTYPE_p_p_char.getCPtr(symbol_name), num_names, name_type_mask, SBFileSpecList.getCPtr(module_list), module_list, SBFileSpecList.getCPtr(comp_unit_list), comp_unit_list), true);
  }

  public SBBreakpoint BreakpointCreateByNames(SWIGTYPE_p_p_char symbol_name, long num_names, long name_type_mask, LanguageType symbol_language, SBFileSpecList module_list, SBFileSpecList comp_unit_list) {
    return new SBBreakpoint(lldbJNI.SBTarget_BreakpointCreateByNames__SWIG_1(swigCPtr, this, SWIGTYPE_p_p_char.getCPtr(symbol_name), num_names, name_type_mask, symbol_language.swigValue(), SBFileSpecList.getCPtr(module_list), module_list, SBFileSpecList.getCPtr(comp_unit_list), comp_unit_list), true);
  }

  public SBBreakpoint BreakpointCreateByNames(SWIGTYPE_p_p_char symbol_name, long num_names, long name_type_mask, LanguageType symbol_language, java.math.BigInteger offset, SBFileSpecList module_list, SBFileSpecList comp_unit_list) {
    return new SBBreakpoint(lldbJNI.SBTarget_BreakpointCreateByNames__SWIG_2(swigCPtr, this, SWIGTYPE_p_p_char.getCPtr(symbol_name), num_names, name_type_mask, symbol_language.swigValue(), offset, SBFileSpecList.getCPtr(module_list), module_list, SBFileSpecList.getCPtr(comp_unit_list), comp_unit_list), true);
  }

  public SBBreakpoint BreakpointCreateByRegex(String symbol_name_regex, String module_name) {
    return new SBBreakpoint(lldbJNI.SBTarget_BreakpointCreateByRegex__SWIG_0(swigCPtr, this, symbol_name_regex, module_name), true);
  }

  public SBBreakpoint BreakpointCreateByRegex(String symbol_name_regex) {
    return new SBBreakpoint(lldbJNI.SBTarget_BreakpointCreateByRegex__SWIG_1(swigCPtr, this, symbol_name_regex), true);
  }

  public SBBreakpoint BreakpointCreateByRegex(String symbol_name_regex, LanguageType symbol_language, SBFileSpecList module_list, SBFileSpecList comp_unit_list) {
    return new SBBreakpoint(lldbJNI.SBTarget_BreakpointCreateByRegex__SWIG_2(swigCPtr, this, symbol_name_regex, symbol_language.swigValue(), SBFileSpecList.getCPtr(module_list), module_list, SBFileSpecList.getCPtr(comp_unit_list), comp_unit_list), true);
  }

  public SBBreakpoint BreakpointCreateBySourceRegex(String source_regex, SBFileSpec source_file, String module_name) {
    return new SBBreakpoint(lldbJNI.SBTarget_BreakpointCreateBySourceRegex__SWIG_0(swigCPtr, this, source_regex, SBFileSpec.getCPtr(source_file), source_file, module_name), true);
  }

  public SBBreakpoint BreakpointCreateBySourceRegex(String source_regex, SBFileSpec source_file) {
    return new SBBreakpoint(lldbJNI.SBTarget_BreakpointCreateBySourceRegex__SWIG_1(swigCPtr, this, source_regex, SBFileSpec.getCPtr(source_file), source_file), true);
  }

  public SBBreakpoint BreakpointCreateBySourceRegex(String source_regex, SBFileSpecList module_list, SBFileSpecList file_list) {
    return new SBBreakpoint(lldbJNI.SBTarget_BreakpointCreateBySourceRegex__SWIG_2(swigCPtr, this, source_regex, SBFileSpecList.getCPtr(module_list), module_list, SBFileSpecList.getCPtr(file_list), file_list), true);
  }

  public SBBreakpoint BreakpointCreateBySourceRegex(String source_regex, SBFileSpecList module_list, SBFileSpecList source_file, SBStringList func_names) {
    return new SBBreakpoint(lldbJNI.SBTarget_BreakpointCreateBySourceRegex__SWIG_3(swigCPtr, this, source_regex, SBFileSpecList.getCPtr(module_list), module_list, SBFileSpecList.getCPtr(source_file), source_file, SBStringList.getCPtr(func_names), func_names), true);
  }

  public SBBreakpoint BreakpointCreateForException(LanguageType language, boolean catch_bp, boolean throw_bp) {
    return new SBBreakpoint(lldbJNI.SBTarget_BreakpointCreateForException(swigCPtr, this, language.swigValue(), catch_bp, throw_bp), true);
  }

  public SBBreakpoint BreakpointCreateByAddress(java.math.BigInteger address) {
    return new SBBreakpoint(lldbJNI.SBTarget_BreakpointCreateByAddress(swigCPtr, this, address), true);
  }

  public SBEnvironment GetEnvironment() {
    return new SBEnvironment(lldbJNI.SBTarget_GetEnvironment(swigCPtr, this), true);
  }

  public SBBreakpoint BreakpointCreateBySBAddress(SBAddress sb_address) {
    return new SBBreakpoint(lldbJNI.SBTarget_BreakpointCreateBySBAddress(swigCPtr, this, SBAddress.getCPtr(sb_address), sb_address), true);
  }

  public SBBreakpoint BreakpointCreateFromScript(String class_name, SBStructuredData extra_args, SBFileSpecList module_list, SBFileSpecList file_list, boolean request_hardware) {
    return new SBBreakpoint(lldbJNI.SBTarget_BreakpointCreateFromScript__SWIG_0(swigCPtr, this, class_name, SBStructuredData.getCPtr(extra_args), extra_args, SBFileSpecList.getCPtr(module_list), module_list, SBFileSpecList.getCPtr(file_list), file_list, request_hardware), true);
  }

  public SBBreakpoint BreakpointCreateFromScript(String class_name, SBStructuredData extra_args, SBFileSpecList module_list, SBFileSpecList file_list) {
    return new SBBreakpoint(lldbJNI.SBTarget_BreakpointCreateFromScript__SWIG_1(swigCPtr, this, class_name, SBStructuredData.getCPtr(extra_args), extra_args, SBFileSpecList.getCPtr(module_list), module_list, SBFileSpecList.getCPtr(file_list), file_list), true);
  }

  public long GetNumBreakpoints() {
    return lldbJNI.SBTarget_GetNumBreakpoints(swigCPtr, this);
  }

  public SBBreakpoint GetBreakpointAtIndex(long idx) {
    return new SBBreakpoint(lldbJNI.SBTarget_GetBreakpointAtIndex(swigCPtr, this, idx), true);
  }

  public boolean BreakpointDelete(int break_id) {
    return lldbJNI.SBTarget_BreakpointDelete(swigCPtr, this, break_id);
  }

  public SBBreakpoint FindBreakpointByID(int break_id) {
    return new SBBreakpoint(lldbJNI.SBTarget_FindBreakpointByID(swigCPtr, this, break_id), true);
  }

  public boolean FindBreakpointsByName(String name, SBBreakpointList bkpt_list) {
    return lldbJNI.SBTarget_FindBreakpointsByName(swigCPtr, this, name, SBBreakpointList.getCPtr(bkpt_list), bkpt_list);
  }

  public void DeleteBreakpointName(String name) {
    lldbJNI.SBTarget_DeleteBreakpointName(swigCPtr, this, name);
  }

  public void GetBreakpointNames(SBStringList names) {
    lldbJNI.SBTarget_GetBreakpointNames(swigCPtr, this, SBStringList.getCPtr(names), names);
  }

  public boolean EnableAllBreakpoints() {
    return lldbJNI.SBTarget_EnableAllBreakpoints(swigCPtr, this);
  }

  public boolean DisableAllBreakpoints() {
    return lldbJNI.SBTarget_DisableAllBreakpoints(swigCPtr, this);
  }

  public boolean DeleteAllBreakpoints() {
    return lldbJNI.SBTarget_DeleteAllBreakpoints(swigCPtr, this);
  }

  public SBError BreakpointsCreateFromFile(SBFileSpec source_file, SBBreakpointList bkpt_list) {
    return new SBError(lldbJNI.SBTarget_BreakpointsCreateFromFile__SWIG_0(swigCPtr, this, SBFileSpec.getCPtr(source_file), source_file, SBBreakpointList.getCPtr(bkpt_list), bkpt_list), true);
  }

  public SBError BreakpointsCreateFromFile(SBFileSpec source_file, SBStringList matching_names, SBBreakpointList new_bps) {
    return new SBError(lldbJNI.SBTarget_BreakpointsCreateFromFile__SWIG_1(swigCPtr, this, SBFileSpec.getCPtr(source_file), source_file, SBStringList.getCPtr(matching_names), matching_names, SBBreakpointList.getCPtr(new_bps), new_bps), true);
  }

  public SBError BreakpointsWriteToFile(SBFileSpec dest_file) {
    return new SBError(lldbJNI.SBTarget_BreakpointsWriteToFile__SWIG_0(swigCPtr, this, SBFileSpec.getCPtr(dest_file), dest_file), true);
  }

  public SBError BreakpointsWriteToFile(SBFileSpec dest_file, SBBreakpointList bkpt_list, boolean append) {
    return new SBError(lldbJNI.SBTarget_BreakpointsWriteToFile__SWIG_1(swigCPtr, this, SBFileSpec.getCPtr(dest_file), dest_file, SBBreakpointList.getCPtr(bkpt_list), bkpt_list, append), true);
  }

  public SBError BreakpointsWriteToFile(SBFileSpec dest_file, SBBreakpointList bkpt_list) {
    return new SBError(lldbJNI.SBTarget_BreakpointsWriteToFile__SWIG_2(swigCPtr, this, SBFileSpec.getCPtr(dest_file), dest_file, SBBreakpointList.getCPtr(bkpt_list), bkpt_list), true);
  }

  public long GetNumWatchpoints() {
    return lldbJNI.SBTarget_GetNumWatchpoints(swigCPtr, this);
  }

  public SBWatchpoint GetWatchpointAtIndex(long idx) {
    return new SBWatchpoint(lldbJNI.SBTarget_GetWatchpointAtIndex(swigCPtr, this, idx), true);
  }

  public boolean DeleteWatchpoint(int watch_id) {
    return lldbJNI.SBTarget_DeleteWatchpoint(swigCPtr, this, watch_id);
  }

  public SBWatchpoint FindWatchpointByID(int watch_id) {
    return new SBWatchpoint(lldbJNI.SBTarget_FindWatchpointByID(swigCPtr, this, watch_id), true);
  }

  public boolean EnableAllWatchpoints() {
    return lldbJNI.SBTarget_EnableAllWatchpoints(swigCPtr, this);
  }

  public boolean DisableAllWatchpoints() {
    return lldbJNI.SBTarget_DisableAllWatchpoints(swigCPtr, this);
  }

  public boolean DeleteAllWatchpoints() {
    return lldbJNI.SBTarget_DeleteAllWatchpoints(swigCPtr, this);
  }

  public SBWatchpoint WatchAddress(java.math.BigInteger addr, long size, boolean read, boolean write, SBError error) {
    return new SBWatchpoint(lldbJNI.SBTarget_WatchAddress(swigCPtr, this, addr, size, read, write, SBError.getCPtr(error), error), true);
  }

  public SBBroadcaster GetBroadcaster() {
    return new SBBroadcaster(lldbJNI.SBTarget_GetBroadcaster(swigCPtr, this), true);
  }

  public SBValue CreateValueFromAddress(String name, SBAddress addr, SBType type) {
    return new SBValue(lldbJNI.SBTarget_CreateValueFromAddress(swigCPtr, this, name, SBAddress.getCPtr(addr), addr, SBType.getCPtr(type), type), true);
  }

  public SBValue CreateValueFromData(String name, SBData data, SBType type) {
    return new SBValue(lldbJNI.SBTarget_CreateValueFromData(swigCPtr, this, name, SBData.getCPtr(data), data, SBType.getCPtr(type), type), true);
  }

  public SBValue CreateValueFromExpression(String name, String expr) {
    return new SBValue(lldbJNI.SBTarget_CreateValueFromExpression(swigCPtr, this, name, expr), true);
  }

  public SBInstructionList ReadInstructions(SBAddress base_addr, long count) {
    return new SBInstructionList(lldbJNI.SBTarget_ReadInstructions__SWIG_0(swigCPtr, this, SBAddress.getCPtr(base_addr), base_addr, count), true);
  }

  public SBInstructionList ReadInstructions(SBAddress base_addr, long count, String flavor_string) {
    return new SBInstructionList(lldbJNI.SBTarget_ReadInstructions__SWIG_1(swigCPtr, this, SBAddress.getCPtr(base_addr), base_addr, count, flavor_string), true);
  }

  public SBInstructionList GetInstructions(SBAddress base_addr, SWIGTYPE_p_void buf, long size) {
    return new SBInstructionList(lldbJNI.SBTarget_GetInstructions(swigCPtr, this, SBAddress.getCPtr(base_addr), base_addr, SWIGTYPE_p_void.getCPtr(buf), size), true);
  }

  public SBInstructionList GetInstructionsWithFlavor(SBAddress base_addr, String flavor_string, SWIGTYPE_p_void buf, long size) {
    return new SBInstructionList(lldbJNI.SBTarget_GetInstructionsWithFlavor(swigCPtr, this, SBAddress.getCPtr(base_addr), base_addr, flavor_string, SWIGTYPE_p_void.getCPtr(buf), size), true);
  }

  public SBSymbolContextList FindSymbols(String name, SymbolType type) {
    return new SBSymbolContextList(lldbJNI.SBTarget_FindSymbols__SWIG_0(swigCPtr, this, name, type.swigValue()), true);
  }

  public SBSymbolContextList FindSymbols(String name) {
    return new SBSymbolContextList(lldbJNI.SBTarget_FindSymbols__SWIG_1(swigCPtr, this, name), true);
  }

  public boolean GetDescription(SBStream description, DescriptionLevel description_level) {
    return lldbJNI.SBTarget_GetDescription(swigCPtr, this, SBStream.getCPtr(description), description, description_level.swigValue());
  }

  public java.math.BigInteger GetStackRedZoneSize() {
    return lldbJNI.SBTarget_GetStackRedZoneSize(swigCPtr, this);
  }

  public SBLaunchInfo GetLaunchInfo() {
    return new SBLaunchInfo(lldbJNI.SBTarget_GetLaunchInfo(swigCPtr, this), true);
  }

  public void SetLaunchInfo(SBLaunchInfo launch_info) {
    lldbJNI.SBTarget_SetLaunchInfo(swigCPtr, this, SBLaunchInfo.getCPtr(launch_info), launch_info);
  }

  public void SetCollectingStats(boolean v) {
    lldbJNI.SBTarget_SetCollectingStats(swigCPtr, this, v);
  }

  public boolean GetCollectingStats() {
    return lldbJNI.SBTarget_GetCollectingStats(swigCPtr, this);
  }

  public SBStructuredData GetStatistics() {
    return new SBStructuredData(lldbJNI.SBTarget_GetStatistics(swigCPtr, this), true);
  }

  public SBValue EvaluateExpression(String expr) {
    return new SBValue(lldbJNI.SBTarget_EvaluateExpression__SWIG_0(swigCPtr, this, expr), true);
  }

  public SBValue EvaluateExpression(String expr, SBExpressionOptions options) {
    return new SBValue(lldbJNI.SBTarget_EvaluateExpression__SWIG_1(swigCPtr, this, expr, SBExpressionOptions.getCPtr(options), options), true);
  }

  public String __str__() {
    return lldbJNI.SBTarget___str__(swigCPtr, this);
  }

  public final static int eBroadcastBitBreakpointChanged = 1 << 0;
  public final static int eBroadcastBitModulesLoaded     = 1 << 1;
  public final static int eBroadcastBitModulesUnloaded   = 1 << 2;
  public final static int eBroadcastBitWatchpointChanged = 1 << 3;
  public final static int eBroadcastBitSymbolsLoaded     = 1 << 4;

}
