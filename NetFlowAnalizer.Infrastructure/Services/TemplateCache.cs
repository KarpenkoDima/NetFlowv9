using NetFlowAnalizer.Core.Models;
using NetFlowAnalizer.Core.Services;

namespace NetFlowAnalizer.Infrastructure.Services;

/// <summary>
/// In-memory template cache implementation
/// </summary>
public class TemplateCache : ITemplateCache
{
    private readonly Dictionary<uint, Dictionary<ushort, TemplateRecord>> _cache = new();
    private readonly object _lock = new();

    public void AddTemplate(uint sourceId, TemplateRecord template)
    {
        lock (_lock)
        {
            if (!_cache.ContainsKey(sourceId))
                _cache[sourceId] = new Dictionary<ushort, TemplateRecord>();

            _cache[sourceId][template.TemplateId] = template;
        }
    }

    public TemplateRecord? GetTemplate(uint sourceId, ushort templateId)
    {
        lock (_lock)
        {
            if (_cache.TryGetValue(sourceId, out var templates))
                if (templates.TryGetValue(templateId, out var template))
                    return template;

            return null;
        }
    }

    public Dictionary<uint, Dictionary<ushort, TemplateRecord>> GetAllTemplates()
    {
        lock (_lock)
        {
            // Return a deep copy to avoid external modifications
            var result = new Dictionary<uint, Dictionary<ushort, TemplateRecord>>();
            foreach (var kvp in _cache)
            {
                result[kvp.Key] = new Dictionary<ushort, TemplateRecord>(kvp.Value);
            }
            return result;
        }
    }

    public void Clear()
    {
        lock (_lock)
        {
            _cache.Clear();
        }
    }
}
