package agent.lldb.lldb;

import static org.junit.Assume.assumeTrue;

import SWIG.*;
import agent.lldb.manager.LldbEvent;
import agent.lldb.manager.LldbManager;
import agent.lldb.manager.evt.LldbBreakpointModifiedEvent;
import agent.lldb.manager.evt.LldbConsoleOutputEvent;
import agent.lldb.manager.evt.LldbModuleLoadedEvent;
import agent.lldb.manager.evt.LldbModuleUnloadedEvent;
import agent.lldb.manager.evt.LldbStateChangedEvent;
import agent.lldb.manager.evt.LldbThreadSelectedEvent;
import ghidra.comm.util.BitmaskSet;
import ghidra.util.Msg;

public class DebugClientImpl implements DebugClient {

	private LldbManager manager;
	private SBDebugger sbd;
	private SBTarget session;
	private SBEvent event;
	private DebugOutputCallbacks ocb;
	private DebugEventCallbacks ecb;
	private SBCommandInterpreter cmd;

	public DebugClientImpl() {
	}

	@Override
	public DebugClient createClient() {
		try {
			System.load("/Users/llero/git/llvm-build/lib/liblldb.dylib");
		}
		catch (UnsatisfiedLinkError ex) {
			assumeTrue("liblldb.dylib not found. Probably not OSX here.", false);
		}
		SBDebugger.InitializeWithErrorHandling();
		event = new SBEvent();
		sbd = SBDebugger.Create();
		cmd = sbd.GetCommandInterpreter();
		return this;
	}
	
	public SBDebugger getDebugger() {
		return sbd;
	}
	
	@Override
	public SBListener getListener() {
		return sbd.GetListener();
	}

	@Override
	public void endSessionReentrant() {
		// TODO Auto-generated method stub
		
	}

	@Override
	public DebugServerId getLocalServer() {
		return new DebugServerId(0);
	}

	@Override
	public void attachKernel(long flags, String options) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void startProcessServer(String options) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public DebugServerId connectProcessServer(String options) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public boolean dispatchCallbacks(int timeout) {
		return false;
	}

	@Override
	public void flushCallbacks() {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void exitDispatch(DebugClient client) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void attachProcess(DebugServerId si, String processId, BitmaskSet<DebugAttachFlags> attachFlags) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void createProcess(DebugServerId si, String commandLine, BitmaskSet<DebugCreateFlags> createFlags) {
		session = connectSession("/opt/X11/bin/xclock-x86_64");
		SBListener listener = new SBListener();
		SBError error = new SBError();
		SBProcess process = session.Launch(listener, null, null, "", "", "", "", 0, true, error);
		//SBProcess process = session.LaunchSimple(null, null, null);
		/*
		listener = new SBListener(process.GetProcessID().toString());
		broadcaster = process.GetBroadcaster();
		broadcaster.AddListener(listener, SBProcess.eBroadcastBitStateChanged);
		event = new SBEvent();
		executor = new LldbClientThreadExecutor(() -> createClient());
		*/
	}

	@Override
	public void createProcessAndAttach(DebugServerId si, String commandLine, BitmaskSet<DebugCreateFlags> createFlags,
			int processId, BitmaskSet<DebugAttachFlags> attachFlags) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void startServer(String options) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void waitForProcessServerEnd(int timeout) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void terminateCurrentProcess() {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void detachCurrentProcess() {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void abandonCurrentProcess() {
		// TODO Auto-generated method stub
		
	}

	@Override
	public SBTarget connectSession(String commandLine) {
		return sbd.CreateTarget(commandLine);
	}

	@Override
	public void endSession(DebugEndSessionFlags flags) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void openDumpFileWide(String fileName) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public SBEvent waitForEvent() {
		boolean eventFound = getListener().WaitForEvent(-1, event);
		if (eventFound) {
			return event;
		}
		return null;
	}

	public void translateAndFireEvent(SBEvent evt) {
		manager.setCurrentEvent(evt);
		long type = evt.GetType();
		if (SBTarget.EventIsTargetEvent(evt)) {
			if ((type & SBTarget.eBroadcastBitBreakpointChanged) != 0) {
				Msg.info(this, "*** Breakpoint Changed: " + evt.GetType());
				processEvent(new LldbBreakpointModifiedEvent(null));
			}
			if ((type & SBTarget.eBroadcastBitModulesLoaded) != 0) {
				Msg.info(this, "*** Module Loaded: " + evt.GetType());
				processEvent(new LldbModuleLoadedEvent(new DebugModuleInfo(evt)));
			}
			if ((type & SBTarget.eBroadcastBitModulesUnloaded) != 0) {
				Msg.info(this, "*** Module Unloaded: " + evt.GetType());
				processEvent(new LldbModuleUnloadedEvent(null));
			}
			if ((type & SBTarget.eBroadcastBitWatchpointChanged) != 0) {
				Msg.info(this, "*** Watchpoint Changed: " + evt.GetType());
				//fireEvent(new LldbWatchpointModifiedEvent(null));
			}
			if ((type & SBTarget.eBroadcastBitSymbolsLoaded) != 0) {
				Msg.info(this, "*** Symbols Loaded: " + evt.GetType());
				//fireEvent(new LldbSymbolsLoadedEvent(null));
			}
		}
		
		if (SBProcess.EventIsProcessEvent(evt)) {
			if ((type & SBProcess.eBroadcastBitStateChanged) != 0) {
				Msg.info(this, "*** State Changed: " + evt.GetType());
				processEvent(new LldbStateChangedEvent(new DebugEventInfo(evt)));
			}
			if ((type & SBProcess.eBroadcastBitInterrupt) != 0) {
				Msg.info(this, "*** Interrupt: " + evt.GetType());
				//fireEvent(new LldbInterrupt(null));
			}
			if ((type & SBProcess.eBroadcastBitSTDOUT) != 0) {
				Msg.info(this, "*** Console STDOU: " + evt.GetType());
				processEvent(new LldbConsoleOutputEvent(0, null));
			}
			if ((type & SBProcess.eBroadcastBitSTDERR) != 0) {
				Msg.info(this, "*** Console STDERR: " + evt.GetType());
				processEvent(new LldbConsoleOutputEvent(0, null));
			}
			if ((type & SBProcess.eBroadcastBitProfileData) != 0) {
				Msg.info(this, "*** Profile Data Added: " + evt.GetType());
				//fireEvent(new LldbProfileDataEvent(null));
			}
			if ((type & SBProcess.eBroadcastBitStructuredData) != 0) {
				Msg.info(this, "*** Structured Data Added: " + evt.GetType());
				//fireEvent(new LldbStructuredDataEvent(null));
			}
		}
		
		if (SBThread.EventIsThreadEvent(evt)) {
			if ((type & SBThread.eBroadcastBitStackChanged) != 0) {
				Msg.info(this, "*** Stack Changed: " + evt.GetType());
				//fireEvent(new LldbStackChangedEvent(null));
			}
			if ((type & SBThread.eBroadcastBitThreadSuspended) != 0) {
				Msg.info(this, "*** Thread Suspended: " + evt.GetType());
				//fireEvent(new LldbThreadSuspendedEvent(null));
			}
			if ((type & SBThread.eBroadcastBitThreadResumed) != 0) {
				Msg.info(this, "*** Thread Resumed: " + evt.GetType());
				//fireEvent(new LldbThreadResumedEvent(null));
			}
			if ((type & SBThread.eBroadcastBitSelectedFrameChanged) != 0) {
				Msg.info(this, "*** Frame Selected: " + evt.GetType());
				//fireEvent(new LldbSelectedFrameChangedEvent(null));
			}
			if ((type & SBThread.eBroadcastBitThreadSelected) != 0) {
				Msg.info(this, "*** Thread Selected: " + evt.GetType());
				processEvent(new LldbThreadSelectedEvent(null, null, null));
			}
		}
	}

	public void processEvent(LldbEvent<?> lldbEvt) {
		manager.processEvent(lldbEvt);
	}

	@Override
	public DebugStatus getExecutionStatus() {
		StateType state = manager.getState();
		return DebugStatus.fromArgument(state);
	}

	@Override
	public void setOutputCallbacks(DebugOutputCallbacks cb) {
		this.ocb = cb;
	}

	@Override
	public void setEventCallbacks(DebugEventCallbacks cb) {
		this.ecb = cb;
	}

	@Override
	public boolean getInterrupt() {
		return false;
	}

	@Override
	public void setManager(LldbManager manager) {
		this.manager = manager;
	}

	@Override
	public void addBroadcaster(Object object) {
		if (object instanceof SBCommandInterpreter) {
			SBCommandInterpreter interpreter = (SBCommandInterpreter) object;
			interpreter.GetBroadcaster().AddListener(getListener(), ChangeSessionState.SESSION_ALL.getMask());
		}
		if (object instanceof SBTarget) {
			SBTarget session = (SBTarget) object;
			session.GetBroadcaster().AddListener(getListener(), ChangeSessionState.SESSION_ALL.getMask());
		}
		if (object instanceof SBProcess) {
			SBProcess process = (SBProcess) object;
			process.GetBroadcaster().AddListener(getListener(), ChangeProcessState.PROCESS_ALL.getMask());
		}
	}

	@Override
	public void execute(String command) {
		SBCommandReturnObject res = new SBCommandReturnObject();
		cmd.HandleCommand(command, res);
		if (res.GetErrorSize() > 0) {
			ocb.output(DebugOutputFlags.DEBUG_OUTPUT_ERROR.ordinal(), res.GetError());
		}
		if (res.GetOutputSize() > 0) {
			ocb.output(DebugOutputFlags.DEBUG_OUTPUT_NORMAL.ordinal(), res.GetOutput());
		}
	}

}
