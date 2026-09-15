# Definition-only helper. Configure is called only by the authorized installer.
if (-not ('CyberDefenderRecoveryPolicy' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
public static class CyberDefenderRecoveryPolicy {
    [StructLayout(LayoutKind.Sequential)] struct Action { public uint Type; public uint Delay; }
    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)] struct Failure {
        public uint Reset; public IntPtr Reboot; public IntPtr Command; public uint Count; public IntPtr Actions;
    }
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern IntPtr OpenSCManager(string machine, string database, uint access);
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern IntPtr OpenService(IntPtr manager, string name, uint access);
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern bool ChangeServiceConfig2(IntPtr service, uint level, ref Failure data);
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern bool QueryServiceConfig2(IntPtr service, uint level, IntPtr buffer, uint size, out uint needed);
    [DllImport("advapi32.dll")] static extern bool CloseServiceHandle(IntPtr handle);
    public static uint[] ExpectedActions() { return new uint[] {1,5000,1,15000,1,60000,0,0}; }
    public static void Configure(string name) {
        if (name != "CyberDefenderAgent" && name != "CyberDefenderControlPlane" && name != "CyberDefenderOwnerUI")
            throw new ArgumentException("Unknown service");
        IntPtr manager=IntPtr.Zero, service=IntPtr.Zero, actions=IntPtr.Zero, query=IntPtr.Zero;
        try {
            manager=OpenSCManager(null,null,1);
            if(manager==IntPtr.Zero) throw new Win32Exception();
            service=OpenService(manager,name,3); // QUERY_CONFIG | CHANGE_CONFIG
            if(service==IntPtr.Zero) throw new Win32Exception();
            int stride=Marshal.SizeOf(typeof(Action)); actions=Marshal.AllocHGlobal(4*stride);
            uint[] expected=ExpectedActions();
            for(int i=0;i<4;i++) Marshal.StructureToPtr(new Action {Type=expected[2*i],Delay=expected[2*i+1]},IntPtr.Add(actions,i*stride),false);
            Failure value=new Failure {Reset=86400,Count=4,Actions=actions};
            if(!ChangeServiceConfig2(service,2,ref value)) throw new Win32Exception();
            uint needed; QueryServiceConfig2(service,2,IntPtr.Zero,0,out needed);
            if(needed==0 || needed>65536) throw new InvalidOperationException("Recovery query size rejected");
            query=Marshal.AllocHGlobal((int)needed);
            if(!QueryServiceConfig2(service,2,query,needed,out needed)) throw new Win32Exception();
            Failure actual=(Failure)Marshal.PtrToStructure(query,typeof(Failure));
            if(actual.Reset!=86400 || actual.Count!=4) throw new InvalidOperationException("Recovery verification failed");
            for(int i=0;i<4;i++) {
                Action a=(Action)Marshal.PtrToStructure(IntPtr.Add(actual.Actions,i*stride),typeof(Action));
                if(a.Type!=expected[2*i] || a.Delay!=expected[2*i+1]) throw new InvalidOperationException("Recovery action mismatch");
            }
        } finally {
            if(query!=IntPtr.Zero) Marshal.FreeHGlobal(query);
            if(actions!=IntPtr.Zero) Marshal.FreeHGlobal(actions);
            if(service!=IntPtr.Zero) CloseServiceHandle(service);
            if(manager!=IntPtr.Zero) CloseServiceHandle(manager);
        }
    }
}
'@
}
