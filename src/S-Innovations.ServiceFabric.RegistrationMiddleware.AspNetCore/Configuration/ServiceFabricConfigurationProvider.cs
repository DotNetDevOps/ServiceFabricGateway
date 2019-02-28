using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using System;
using System.Fabric;

namespace SInnovations.ServiceFabric.RegistrationMiddleware.AspNetCore.Configuration
{
    public class ServiceFabricConfigurationProvider : ConfigurationProvider
    {
        private readonly string _packageName;
        private readonly CodePackageActivationContext _context;
        

        public ServiceFabricConfigurationProvider(string packageName)
        {
            try
            {
                _packageName = packageName;
                _context = FabricRuntime.GetActivationContext();
                _context.ConfigurationPackageModifiedEvent += (sender, e) =>
                {
                    this.LoadPackage(e.NewPackage, reload: true);
                    this.OnReload(); // Notify the change
                };
            }
            catch (Exception)
            {

            }

            
        }

        public override void Load()
        {
            var config = _context.GetConfigurationPackageObject(_packageName);
            LoadPackage(config);
        }

        private void LoadPackage(ConfigurationPackage config, bool reload = false)
        {
            if (reload)
            {
                Data.Clear();  // Rememove the old keys on re-load
            }
            foreach (var section in config.Settings.Sections)
            {
                foreach (var param in section.Parameters)
                {
                    
                    try
                    {
                        Data[$"{section.Name}:{param.Name}"] = param.IsEncrypted && !string.IsNullOrEmpty(param.Value) ? param.DecryptValue().ToUnsecureString() : param.Value;
                    }catch(Exception )
                    {
                        Console.WriteLine($"Failed to add \"{section.Name}:{param.Name}\" from {param.Value} encryption={param.IsEncrypted}");
                        //logger.LogWarning("Failed to add {key} from {value} encryption={encryption}", $"{section.Name}:{param.Name}",param.Value, param.IsEncrypted);
                    }
                }
            }
        }

    }
}
