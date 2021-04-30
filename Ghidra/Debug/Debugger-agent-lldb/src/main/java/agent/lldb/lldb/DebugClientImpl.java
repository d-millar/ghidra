package agent.lldb.lldb;

import static org.junit.Assume.assumeTrue;

import SWIG.SBDebugger;
import SWIG.SBListener;
import SWIG.SBProcess;
import SWIG.SBTarget;
import ghidra.comm.util.BitmaskSet;

public class DebugClientImpl implements DebugClient {

	private SBDebugger sbd;

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
		sbd = SBDebugger.Create();
		return this;
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
		// TODO Auto-generated method stub
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
		SBTarget session = connectSession(commandLine.split(" ")[0]);
		SBProcess process = session.LaunchSimple(null, null, null);
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

}
