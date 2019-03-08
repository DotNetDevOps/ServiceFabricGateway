using Microsoft.ServiceFabric.Services.Remoting;
using Microsoft.ServiceFabric.Services.Remoting.FabricTransport;
using System;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;

 
namespace SInnovations.ServiceFabric.Gateway.Common.Services
{
    public struct ExpirationMetadata<T>
    {
        public T Result { get; set; }

        public DateTimeOffset ValidUntil { get; set; }
    }

    public class AsyncExpiringLazy<T>
    {
        private readonly SemaphoreSlim _syncLock = new SemaphoreSlim(initialCount: 1);
        private readonly Func<ExpirationMetadata<T>, Task<ExpirationMetadata<T>>> _valueProvider;
        private ExpirationMetadata<T> _value;

        public AsyncExpiringLazy(Func<ExpirationMetadata<T>, Task<ExpirationMetadata<T>>> valueProvider)
        {
            if (valueProvider == null) throw new ArgumentNullException(nameof(valueProvider));
            _valueProvider = valueProvider;
        }

        private bool IsValueCreatedInternal => _value.Result != null && _value.ValidUntil > DateTimeOffset.UtcNow;

        public async Task<bool> IsValueCreated()
        {
            await _syncLock.WaitAsync().ConfigureAwait(false);
            try
            {
                return IsValueCreatedInternal;
            }
            finally
            {
                _syncLock.Release();
            }
        }

        public TaskAwaiter<T> GetAwaiter()
        {
            return Value().GetAwaiter();
        }

        public async Task<T> Value()
        {
            await _syncLock.WaitAsync().ConfigureAwait(false);
            try
            {
                if (IsValueCreatedInternal)
                {
                    return _value.Result;
                }

                var result = await _valueProvider(_value).ConfigureAwait(false);
                _value = result;
                return _value.Result;
            }
            finally
            {
                _syncLock.Release();
            }
        }

        public async Task Invalidate()
        {
            await _syncLock.WaitAsync().ConfigureAwait(false);
            _value = default(ExpirationMetadata<T>);
            _syncLock.Release();
        }
    }

    public sealed class AsyncLazy<T>
    {
        /// <summary>
        /// The underlying lazy task.
        /// </summary>
        private readonly Lazy<Task<T>> instance;

        /// <summary>
        /// Initializes a new instance of the <see cref="AsyncLazy&lt;T&gt;"/> class.
        /// </summary>
        /// <param name="factory">The delegate that is invoked on a background thread to produce the value when it is needed.</param>
        public AsyncLazy(Func<T> factory)
        {
            instance = new Lazy<Task<T>>(() => Task.Run(factory));
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="AsyncLazy&lt;T&gt;"/> class.
        /// </summary>
        /// <param name="factory">The asynchronous delegate that is invoked on a background thread to produce the value when it is needed.</param>
        public AsyncLazy(Func<Task<T>> factory)
        {
            instance = new Lazy<Task<T>>(() => Task.Run(factory));
        }

        /// <summary>
        /// Asynchronous infrastructure support. This method permits instances of <see cref="AsyncLazy&lt;T&gt;"/> to be await'ed.
        /// </summary>
        public TaskAwaiter<T> GetAwaiter()
        {
            return instance.Value.GetAwaiter();
        }

        /// <summary>
        /// Starts the asynchronous initialization, if it has not already started.
        /// </summary>
        public void Start()
        {
            var unused = instance.Value;
        }
    }


    public interface IKeyVaultService : IService
    {
        Task<string> GetSecretAsync(string key);
        Task<string[]> GetSecretsAsync(string key);

    }

   

    public interface IAzureADTokenService : IService
    {
        Task<string> GetTokenAsync();
        Task<string> GetTokenForResourceAsync(string resource);
    }

   
}
