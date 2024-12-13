using System.Diagnostics;
using Reloaded.Injector;

namespace Il2CppInjectorR
{
    class MainThread
    {
        public static void Main(string[] args)
        {
            Console.WriteLine("Enter the process name of the game you want to inject.\n(Make sure it's open).");
            //string processName = "TestProj";
            string processName = Console.ReadLine();
            string assemblyPath = Directory.GetCurrentDirectory() + @"\..\Il2cppDumperR.dll";

            Process[] processes = Process.GetProcessesByName(processName);
            Process targetProcess;

            if (processes.Length == 1)
            {
                targetProcess = processes[0];
            }
            else
            {
                Console.WriteLine("Please enter the process ID.");
                targetProcess = Process.GetProcessById(int.Parse(Console.ReadLine()));
            }

            string dumpPath = Path.GetDirectoryName(targetProcess.MainModule.FileName) + @"\il2cpp_classes.json";

            try
            {
                File.Delete(dumpPath);
            }
            catch (Exception e)
            {
                Console.WriteLine("Error deleting file: " + e.Message);
            }

            using (var injector = new Injector(targetProcess))
            {
                injector.Inject(assemblyPath);
                Console.WriteLine("Injected Succesfully!, waiting for dump...");

                // Get Process Execution Directory
                while (!File.Exists(dumpPath))
                {
                    Thread.Sleep(100);
                }

                Console.WriteLine("Dump Done!");
            }



            Console.ReadKey();
        }
    }
}