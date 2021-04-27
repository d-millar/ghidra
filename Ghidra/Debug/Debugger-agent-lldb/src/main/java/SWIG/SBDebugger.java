package SWIG;


/* ----------------------------------------------------------------------------
 * This file was automatically generated by SWIG (http://www.swig.org).
 * Version 4.0.2
 *
 * Do not make changes to this file unless you know what you are doing--modify
 * the SWIG interface file instead.
 * ----------------------------------------------------------------------------- */


public class SBDebugger {
  private transient long swigCPtr;
  protected transient boolean swigCMemOwn;

  protected SBDebugger(long cPtr, boolean cMemoryOwn) {
    swigCMemOwn = cMemoryOwn;
    swigCPtr = cPtr;
  }

  protected static long getCPtr(SBDebugger obj) {
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
        lldbJNI.delete_SBDebugger(swigCPtr);
      }
      swigCPtr = 0;
    }
  }

  public static void Initialize() {
    lldbJNI.SBDebugger_Initialize();
  }

  public static SBError InitializeWithErrorHandling() {
    return new SBError(lldbJNI.SBDebugger_InitializeWithErrorHandling(), true);
  }

  public static void Terminate() {
    lldbJNI.SBDebugger_Terminate();
  }

  public static SBDebugger Create() {
	return new SBDebugger(lldbJNI.SBDebugger_Create__SWIG_0(), true);
  }

  public static SBDebugger Create(boolean source_init_files) {
    return new SBDebugger(lldbJNI.SBDebugger_Create__SWIG_1(source_init_files), true);
  }

  public static SBDebugger Create(boolean source_init_files, SWIGTYPE_p_f_p_q_const__char_p_void__void log_callback, SWIGTYPE_p_void baton) {
    return new SBDebugger(lldbJNI.SBDebugger_Create__SWIG_2(source_init_files, SWIGTYPE_p_f_p_q_const__char_p_void__void.getCPtr(log_callback), SWIGTYPE_p_void.getCPtr(baton)), true);
  }

  public static void Destroy(SBDebugger debugger) {
    lldbJNI.SBDebugger_Destroy(SBDebugger.getCPtr(debugger), debugger);
  }

  public static void MemoryPressureDetected() {
    lldbJNI.SBDebugger_MemoryPressureDetected();
  }

  public SBDebugger() {
    this(lldbJNI.new_SBDebugger__SWIG_0(), true);
  }

  public SBDebugger(SBDebugger rhs) {
    this(lldbJNI.new_SBDebugger__SWIG_1(SBDebugger.getCPtr(rhs), rhs), true);
  }

  public boolean IsValid() {
    return lldbJNI.SBDebugger_IsValid(swigCPtr, this);
  }

  public void Clear() {
    lldbJNI.SBDebugger_Clear(swigCPtr, this);
  }

  public void SetAsync(boolean b) {
    lldbJNI.SBDebugger_SetAsync(swigCPtr, this, b);
  }

  public boolean GetAsync() {
    return lldbJNI.SBDebugger_GetAsync(swigCPtr, this);
  }

  public void SkipLLDBInitFiles(boolean b) {
    lldbJNI.SBDebugger_SkipLLDBInitFiles(swigCPtr, this, b);
  }

  public SWIGTYPE_p_std__shared_ptrT_lldb_private__File_t GetInputFileHandle() {
    return new SWIGTYPE_p_std__shared_ptrT_lldb_private__File_t(lldbJNI.SBDebugger_GetInputFileHandle(swigCPtr, this), true);
  }

  public SWIGTYPE_p_std__shared_ptrT_lldb_private__File_t GetOutputFileHandle() {
    return new SWIGTYPE_p_std__shared_ptrT_lldb_private__File_t(lldbJNI.SBDebugger_GetOutputFileHandle(swigCPtr, this), true);
  }

  public SWIGTYPE_p_std__shared_ptrT_lldb_private__File_t GetErrorFileHandle() {
    return new SWIGTYPE_p_std__shared_ptrT_lldb_private__File_t(lldbJNI.SBDebugger_GetErrorFileHandle(swigCPtr, this), true);
  }

  public SBError SetInputFile(SBFile file) {
    return new SBError(lldbJNI.SBDebugger_SetInputFile__SWIG_0(swigCPtr, this, SBFile.getCPtr(file), file), true);
  }

  public SBError SetOutputFile(SBFile file) {
    return new SBError(lldbJNI.SBDebugger_SetOutputFile__SWIG_0(swigCPtr, this, SBFile.getCPtr(file), file), true);
  }

  public SBError SetErrorFile(SBFile file) {
    return new SBError(lldbJNI.SBDebugger_SetErrorFile__SWIG_0(swigCPtr, this, SBFile.getCPtr(file), file), true);
  }

  public SBError SetInputFile(SWIGTYPE_p_std__shared_ptrT_lldb_private__File_t file) {
    return new SBError(lldbJNI.SBDebugger_SetInputFile__SWIG_1(swigCPtr, this, SWIGTYPE_p_std__shared_ptrT_lldb_private__File_t.getCPtr(file)), true);
  }

  public SBError SetOutputFile(SWIGTYPE_p_std__shared_ptrT_lldb_private__File_t file) {
    return new SBError(lldbJNI.SBDebugger_SetOutputFile__SWIG_1(swigCPtr, this, SWIGTYPE_p_std__shared_ptrT_lldb_private__File_t.getCPtr(file)), true);
  }

  public SBError SetErrorFile(SWIGTYPE_p_std__shared_ptrT_lldb_private__File_t file) {
    return new SBError(lldbJNI.SBDebugger_SetErrorFile__SWIG_1(swigCPtr, this, SWIGTYPE_p_std__shared_ptrT_lldb_private__File_t.getCPtr(file)), true);
  }

  public SBFile GetInputFile() {
    return new SBFile(lldbJNI.SBDebugger_GetInputFile(swigCPtr, this), true);
  }

  public SBFile GetOutputFile() {
    return new SBFile(lldbJNI.SBDebugger_GetOutputFile(swigCPtr, this), true);
  }

  public SBFile GetErrorFile() {
    return new SBFile(lldbJNI.SBDebugger_GetErrorFile(swigCPtr, this), true);
  }

  public SBCommandInterpreter GetCommandInterpreter() {
    return new SBCommandInterpreter(lldbJNI.SBDebugger_GetCommandInterpreter(swigCPtr, this), true);
  }

  public void HandleCommand(String command) {
    lldbJNI.SBDebugger_HandleCommand(swigCPtr, this, command);
  }

  public SBListener GetListener() {
    return new SBListener(lldbJNI.SBDebugger_GetListener(swigCPtr, this), true);
  }

  public void HandleProcessEvent(SBProcess process, SBEvent event, SBFile out, SBFile err) {
    lldbJNI.SBDebugger_HandleProcessEvent__SWIG_0(swigCPtr, this, SBProcess.getCPtr(process), process, SBEvent.getCPtr(event), event, SBFile.getCPtr(out), out, SBFile.getCPtr(err), err);
  }

  public void HandleProcessEvent(SBProcess process, SBEvent event, SWIGTYPE_p_std__shared_ptrT_lldb_private__File_t arg2, SWIGTYPE_p_std__shared_ptrT_lldb_private__File_t arg3) {
    lldbJNI.SBDebugger_HandleProcessEvent__SWIG_1(swigCPtr, this, SBProcess.getCPtr(process), process, SBEvent.getCPtr(event), event, SWIGTYPE_p_std__shared_ptrT_lldb_private__File_t.getCPtr(arg2), SWIGTYPE_p_std__shared_ptrT_lldb_private__File_t.getCPtr(arg3));
  }

  public SBTarget CreateTarget(String filename, String target_triple, String platform_name, boolean add_dependent_modules, SBError sb_error) {
    return new SBTarget(lldbJNI.SBDebugger_CreateTarget__SWIG_0(swigCPtr, this, filename, target_triple, platform_name, add_dependent_modules, SBError.getCPtr(sb_error), sb_error), true);
  }

  public SBTarget CreateTargetWithFileAndTargetTriple(String filename, String target_triple) {
    return new SBTarget(lldbJNI.SBDebugger_CreateTargetWithFileAndTargetTriple(swigCPtr, this, filename, target_triple), true);
  }

  public SBTarget CreateTargetWithFileAndArch(String filename, String archname) {
    return new SBTarget(lldbJNI.SBDebugger_CreateTargetWithFileAndArch(swigCPtr, this, filename, archname), true);
  }

  public SBTarget CreateTarget(String filename) {
    return new SBTarget(lldbJNI.SBDebugger_CreateTarget__SWIG_1(swigCPtr, this, filename), true);
  }

  public SBTarget GetDummyTarget() {
    return new SBTarget(lldbJNI.SBDebugger_GetDummyTarget(swigCPtr, this), true);
  }

  public boolean DeleteTarget(SBTarget target) {
    return lldbJNI.SBDebugger_DeleteTarget(swigCPtr, this, SBTarget.getCPtr(target), target);
  }

  public SBTarget GetTargetAtIndex(long idx) {
    return new SBTarget(lldbJNI.SBDebugger_GetTargetAtIndex(swigCPtr, this, idx), true);
  }

  public long GetIndexOfTarget(SBTarget target) {
    return lldbJNI.SBDebugger_GetIndexOfTarget(swigCPtr, this, SBTarget.getCPtr(target), target);
  }

  public SBTarget FindTargetWithProcessID(java.math.BigInteger pid) {
    return new SBTarget(lldbJNI.SBDebugger_FindTargetWithProcessID(swigCPtr, this, pid), true);
  }

  public SBTarget FindTargetWithFileAndArch(String filename, String arch) {
    return new SBTarget(lldbJNI.SBDebugger_FindTargetWithFileAndArch(swigCPtr, this, filename, arch), true);
  }

  public long GetNumTargets() {
    return lldbJNI.SBDebugger_GetNumTargets(swigCPtr, this);
  }

  public SBTarget GetSelectedTarget() {
    return new SBTarget(lldbJNI.SBDebugger_GetSelectedTarget(swigCPtr, this), true);
  }

  public void SetSelectedTarget(SBTarget target) {
    lldbJNI.SBDebugger_SetSelectedTarget(swigCPtr, this, SBTarget.getCPtr(target), target);
  }

  public SBPlatform GetSelectedPlatform() {
    return new SBPlatform(lldbJNI.SBDebugger_GetSelectedPlatform(swigCPtr, this), true);
  }

  public void SetSelectedPlatform(SBPlatform platform) {
    lldbJNI.SBDebugger_SetSelectedPlatform(swigCPtr, this, SBPlatform.getCPtr(platform), platform);
  }

  public long GetNumPlatforms() {
    return lldbJNI.SBDebugger_GetNumPlatforms(swigCPtr, this);
  }

  public SBPlatform GetPlatformAtIndex(long idx) {
    return new SBPlatform(lldbJNI.SBDebugger_GetPlatformAtIndex(swigCPtr, this, idx), true);
  }

  public long GetNumAvailablePlatforms() {
    return lldbJNI.SBDebugger_GetNumAvailablePlatforms(swigCPtr, this);
  }

  public SBStructuredData GetAvailablePlatformInfoAtIndex(long idx) {
    return new SBStructuredData(lldbJNI.SBDebugger_GetAvailablePlatformInfoAtIndex(swigCPtr, this, idx), true);
  }

  public SBSourceManager GetSourceManager() {
    return new SBSourceManager(lldbJNI.SBDebugger_GetSourceManager(swigCPtr, this), true);
  }

  public SBError SetCurrentPlatform(String platform_name) {
    return new SBError(lldbJNI.SBDebugger_SetCurrentPlatform(swigCPtr, this, platform_name), true);
  }

  public boolean SetCurrentPlatformSDKRoot(String sysroot) {
    return lldbJNI.SBDebugger_SetCurrentPlatformSDKRoot(swigCPtr, this, sysroot);
  }

  public boolean SetUseExternalEditor(boolean input) {
    return lldbJNI.SBDebugger_SetUseExternalEditor(swigCPtr, this, input);
  }

  public boolean GetUseExternalEditor() {
    return lldbJNI.SBDebugger_GetUseExternalEditor(swigCPtr, this);
  }

  public boolean SetUseColor(boolean use_color) {
    return lldbJNI.SBDebugger_SetUseColor(swigCPtr, this, use_color);
  }

  public boolean GetUseColor() {
    return lldbJNI.SBDebugger_GetUseColor(swigCPtr, this);
  }

  public static boolean GetDefaultArchitecture(String arch_name, long arch_name_len) {
    return lldbJNI.SBDebugger_GetDefaultArchitecture(arch_name, arch_name_len);
  }

  public static boolean SetDefaultArchitecture(String arch_name) {
    return lldbJNI.SBDebugger_SetDefaultArchitecture(arch_name);
  }

  public ScriptLanguage GetScriptingLanguage(String script_language_name) {
    return ScriptLanguage.swigToEnum(lldbJNI.SBDebugger_GetScriptingLanguage(swigCPtr, this, script_language_name));
  }

  public static String GetVersionString() {
    return lldbJNI.SBDebugger_GetVersionString();
  }

  public static String StateAsCString(StateType state) {
    return lldbJNI.SBDebugger_StateAsCString(state.swigValue());
  }

  public static SBStructuredData GetBuildConfiguration() {
    return new SBStructuredData(lldbJNI.SBDebugger_GetBuildConfiguration(), true);
  }

  public static boolean StateIsRunningState(StateType state) {
    return lldbJNI.SBDebugger_StateIsRunningState(state.swigValue());
  }

  public static boolean StateIsStoppedState(StateType state) {
    return lldbJNI.SBDebugger_StateIsStoppedState(state.swigValue());
  }

  public boolean EnableLog(String channel, SWIGTYPE_p_p_char types) {
    return lldbJNI.SBDebugger_EnableLog(swigCPtr, this, channel, SWIGTYPE_p_p_char.getCPtr(types));
  }

  public void SetLoggingCallback(SWIGTYPE_p_f_p_q_const__char_p_void__void log_callback, SWIGTYPE_p_void baton) {
    lldbJNI.SBDebugger_SetLoggingCallback(swigCPtr, this, SWIGTYPE_p_f_p_q_const__char_p_void__void.getCPtr(log_callback), SWIGTYPE_p_void.getCPtr(baton));
  }

  public void DispatchInput(SWIGTYPE_p_void data, long data_len) {
    lldbJNI.SBDebugger_DispatchInput(swigCPtr, this, SWIGTYPE_p_void.getCPtr(data), data_len);
  }

  public void DispatchInputInterrupt() {
    lldbJNI.SBDebugger_DispatchInputInterrupt(swigCPtr, this);
  }

  public void DispatchInputEndOfFile() {
    lldbJNI.SBDebugger_DispatchInputEndOfFile(swigCPtr, this);
  }

  public String GetInstanceName() {
    return lldbJNI.SBDebugger_GetInstanceName(swigCPtr, this);
  }

  public static SBDebugger FindDebuggerWithID(int id) {
    return new SBDebugger(lldbJNI.SBDebugger_FindDebuggerWithID(id), true);
  }

  public static SBError SetInternalVariable(String var_name, String value, String debugger_instance_name) {
    return new SBError(lldbJNI.SBDebugger_SetInternalVariable(var_name, value, debugger_instance_name), true);
  }

  public static SBStringList GetInternalVariableValue(String var_name, String debugger_instance_name) {
    return new SBStringList(lldbJNI.SBDebugger_GetInternalVariableValue(var_name, debugger_instance_name), true);
  }

  public boolean GetDescription(SBStream description) {
    return lldbJNI.SBDebugger_GetDescription(swigCPtr, this, SBStream.getCPtr(description), description);
  }

  public long GetTerminalWidth() {
    return lldbJNI.SBDebugger_GetTerminalWidth(swigCPtr, this);
  }

  public void SetTerminalWidth(long term_width) {
    lldbJNI.SBDebugger_SetTerminalWidth(swigCPtr, this, term_width);
  }

  public java.math.BigInteger GetID() {
    return lldbJNI.SBDebugger_GetID(swigCPtr, this);
  }

  public String GetPrompt() {
    return lldbJNI.SBDebugger_GetPrompt(swigCPtr, this);
  }

  public void SetPrompt(String prompt) {
    lldbJNI.SBDebugger_SetPrompt(swigCPtr, this, prompt);
  }

  public String GetReproducerPath() {
    return lldbJNI.SBDebugger_GetReproducerPath(swigCPtr, this);
  }

  public ScriptLanguage GetScriptLanguage() {
    return ScriptLanguage.swigToEnum(lldbJNI.SBDebugger_GetScriptLanguage(swigCPtr, this));
  }

  public void SetScriptLanguage(ScriptLanguage script_lang) {
    lldbJNI.SBDebugger_SetScriptLanguage(swigCPtr, this, script_lang.swigValue());
  }

  public boolean GetCloseInputOnEOF() {
    return lldbJNI.SBDebugger_GetCloseInputOnEOF(swigCPtr, this);
  }

  public void SetCloseInputOnEOF(boolean b) {
    lldbJNI.SBDebugger_SetCloseInputOnEOF(swigCPtr, this, b);
  }

  public SBTypeCategory GetCategory(String category_name) {
    return new SBTypeCategory(lldbJNI.SBDebugger_GetCategory__SWIG_0(swigCPtr, this, category_name), true);
  }

  public SBTypeCategory GetCategory(LanguageType lang_type) {
    return new SBTypeCategory(lldbJNI.SBDebugger_GetCategory__SWIG_1(swigCPtr, this, lang_type.swigValue()), true);
  }

  public SBTypeCategory CreateCategory(String category_name) {
    return new SBTypeCategory(lldbJNI.SBDebugger_CreateCategory(swigCPtr, this, category_name), true);
  }

  public boolean DeleteCategory(String category_name) {
    return lldbJNI.SBDebugger_DeleteCategory(swigCPtr, this, category_name);
  }

  public long GetNumCategories() {
    return lldbJNI.SBDebugger_GetNumCategories(swigCPtr, this);
  }

  public SBTypeCategory GetCategoryAtIndex(long arg0) {
    return new SBTypeCategory(lldbJNI.SBDebugger_GetCategoryAtIndex(swigCPtr, this, arg0), true);
  }

  public SBTypeCategory GetDefaultCategory() {
    return new SBTypeCategory(lldbJNI.SBDebugger_GetDefaultCategory(swigCPtr, this), true);
  }

  public SBTypeFormat GetFormatForType(SBTypeNameSpecifier arg0) {
    return new SBTypeFormat(lldbJNI.SBDebugger_GetFormatForType(swigCPtr, this, SBTypeNameSpecifier.getCPtr(arg0), arg0), true);
  }

  public SBTypeSummary GetSummaryForType(SBTypeNameSpecifier arg0) {
    return new SBTypeSummary(lldbJNI.SBDebugger_GetSummaryForType(swigCPtr, this, SBTypeNameSpecifier.getCPtr(arg0), arg0), true);
  }

  public SBTypeFilter GetFilterForType(SBTypeNameSpecifier arg0) {
    return new SBTypeFilter(lldbJNI.SBDebugger_GetFilterForType(swigCPtr, this, SBTypeNameSpecifier.getCPtr(arg0), arg0), true);
  }

  public SBTypeSynthetic GetSyntheticForType(SBTypeNameSpecifier arg0) {
    return new SBTypeSynthetic(lldbJNI.SBDebugger_GetSyntheticForType(swigCPtr, this, SBTypeNameSpecifier.getCPtr(arg0), arg0), true);
  }

  public String __str__() {
    return lldbJNI.SBDebugger___str__(swigCPtr, this);
  }

  public void RunCommandInterpreter(boolean auto_handle_events, boolean spawn_thread, SBCommandInterpreterRunOptions options, SWIGTYPE_p_int num_errors, SWIGTYPE_p_bool quit_requested, SWIGTYPE_p_bool stopped_for_crash) {
    lldbJNI.SBDebugger_RunCommandInterpreter(swigCPtr, this, auto_handle_events, spawn_thread, SBCommandInterpreterRunOptions.getCPtr(options), options, SWIGTYPE_p_int.getCPtr(num_errors), SWIGTYPE_p_bool.getCPtr(quit_requested), SWIGTYPE_p_bool.getCPtr(stopped_for_crash));
  }

  public SBError RunREPL(LanguageType language, String repl_options) {
    return new SBError(lldbJNI.SBDebugger_RunREPL(swigCPtr, this, language.swigValue(), repl_options), true);
  }

}
