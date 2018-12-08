using System.Threading;
using System.Threading.Tasks;

namespace SInnovations.ServiceFabric.RegistrationMiddleware.AspNetCore.Services
{
    public interface IApplicationManager
    {
        Task RestartRequestAsync(CancellationToken cancellationToken);
    }

    
}
