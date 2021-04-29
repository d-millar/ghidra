package agent.lldb.lldb;

import SWIG.SBDebugger;
import SWIG.SBListener;
import ghidra.comm.util.BitmaskSet;

public class DebugClientImpl implements DebugClient{

	private SBDebugger sbd;

	public DebugClientImpl() {
	}

	@Override
	public SBDebugger createClient() {
		SBDebugger.InitializeWithErrorHandling();
		sbd = SBDebugger.Create();
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
		// TODO Auto-generated method stub
		return null;
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
		// TODO Auto-generated method stub
		
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
	public void connectSession(int flags) {
		// TODO Auto-generated method stub
		
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
