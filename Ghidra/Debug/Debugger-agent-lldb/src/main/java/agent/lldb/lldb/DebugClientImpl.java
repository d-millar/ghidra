package agent.lldb.lldb;

import static org.junit.Assume.assumeTrue;

import SWIG.SBDebugger;
import SWIG.SBEvent;
import SWIG.SBListener;
import SWIG.SBProcess;
import SWIG.SBTarget;
import SWIG.SBThread;
import SWIG.StateType;
import agent.lldb.manager.LldbEvent;
import agent.lldb.manager.LldbManager;
import agent.lldb.manager.evt.LldbBreakpointModifiedEvent;
import agent.lldb.manager.evt.LldbConsoleOutputEvent;
import agent.lldb.manager.evt.LldbModuleLoadedEvent;
import agent.lldb.manager.evt.LldbModuleUnloadedEvent;
import agent.lldb.manager.evt.LldbStateChangedEvent;
import agent.lldb.manager.evt.LldbThreadSelectedEvent;
import ghidra.comm.util.BitmaskSet;

public class DebugClientImpl implements DebugClient {

	private LldbManager manager;
	private SBDebugger sbd;
	private SBTarget session;
	private SBEvent event;
	private DebugEventCallbacks cb;

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
	public void attachProcess(DebugServerId si, int processId, BitmaskSet<DebugAttachFlags> attachFlags) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void createProcess(DebugServerId si, String commandLine, BitmaskSet<DebugCreateFlags> createFlags) {
		session = connectSession("/opt/X11/bin/xclock");
		session.BreakpointCreateByName("c", "/opt/X11/bin/xclock");
		SBProcess process = session.LaunchSimple(null, null, null);
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
			translateAndFireEvent(event);
			return event;
		}
		return null;
	}

	private void translateAndFireEvent(SBEvent evt) {
		long type = evt.GetType();
		if (SBTarget.EventIsTargetEvent(evt)) {
			if ((type & SBTarget.eBroadcastBitBreakpointChanged) != 0) {
				fireEvent(new LldbBreakpointModifiedEvent(null));
			}
			if ((type & SBTarget.eBroadcastBitModulesLoaded) != 0) {
				fireEvent(new LldbModuleLoadedEvent(null));
			}
			if ((type & SBTarget.eBroadcastBitModulesUnloaded) != 0) {
				fireEvent(new LldbModuleUnloadedEvent(null));
			}
			if ((type & SBTarget.eBroadcastBitWatchpointChanged) != 0) {
				//fireEvent(new LldbWatchpointModifiedEvent(null));
			}
			if ((type & SBTarget.eBroadcastBitSymbolsLoaded) != 0) {
				//fireEvent(new LldbSymbolsLoadedEvent(null));
			}
		}
		
		if (SBProcess.EventIsProcessEvent(evt)) {
			if ((type & SBProcess.eBroadcastBitStateChanged) != 0) {
				fireEvent(new LldbStateChangedEvent(new DebugEventInfo(evt)));
			}
			if ((type & SBProcess.eBroadcastBitInterrupt) != 0) {
				//fireEvent(new LldbInterrupt(null));
			}
			if ((type & SBProcess.eBroadcastBitSTDOUT) != 0) {
				fireEvent(new LldbConsoleOutputEvent(0, null));
			}
			if ((type & SBProcess.eBroadcastBitSTDERR) != 0) {
				fireEvent(new LldbConsoleOutputEvent(0, null));
			}
			if ((type & SBProcess.eBroadcastBitProfileData) != 0) {
				//fireEvent(new LldbProfileDataEvent(null));
			}
			if ((type & SBProcess.eBroadcastBitStructuredData) != 0) {
				//fireEvent(new LldbStructuredDataEvent(null));
			}
		}
		
		if (SBThread.EventIsThreadEvent(evt)) {
			if ((type & SBThread.eBroadcastBitStackChanged) != 0) {
				//fireEvent(new LldbStackChangedEvent(null));
			}
			if ((type & SBThread.eBroadcastBitThreadSuspended) != 0) {
				//fireEvent(new LldbThreadSuspendedEvent(null));
			}
			if ((type & SBThread.eBroadcastBitThreadResumed) != 0) {
				//fireEvent(new LldbThreadResumedEvent(null));
			}
			if ((type & SBThread.eBroadcastBitSelectedFrameChanged) != 0) {
				//fireEvent(new LldbSelectedFrameChangedEvent(null));
			}
			if ((type & SBThread.eBroadcastBitThreadSelected) != 0) {
				fireEvent(new LldbThreadSelectedEvent(null, null, null));
			}
		}
	}

	public void fireEvent(LldbEvent<?> lldbEvt) {
		manager.processEvent(lldbEvt);
	}

	@Override
	public DebugStatus getExecutionStatus() {
		//TODO: THIS NEEDS TO BE FIXED BEFORE ANYTHING CAN RUN
		if  (session == null) return DebugStatus.NO_DEBUGGEE;
		StateType state = manager.getState();
		boolean invalid = state.equals(StateType.eStateInvalid);
		return invalid ? DebugStatus.GO : DebugStatus.BREAK; 
	}

	@Override
	public void setEventCallbacks(DebugEventCallbacks cb) {
		this.cb = cb;
	}

	@Override
	public boolean getInterrupt() {
		return false;
	}

	@Override
	public void setManager(LldbManager manager) {
		this.manager = manager;
	}

}
