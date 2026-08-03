using NetFlowAnalizer.Core.Models;

namespace NetFlowAnalizer.Core.Services;

/// <summary>
/// Interface for caching NetFlow templates
/// </summary>
public interface ITemplateCache
{
    /// <summary>
    /// Add or update a template for a specific source
    /// </summary>
    void AddTemplate(uint sourceId, TemplateRecord template);

    /// <summary>
    /// Get template by source ID and template ID
    /// </summary>
    TemplateRecord? GetTemplate(uint sourceId, ushort templateId);

    /// <summary>
    /// Get all templates grouped by source ID
    /// </summary>
    Dictionary<uint, Dictionary<ushort, TemplateRecord>> GetAllTemplates();

    /// <summary>
    /// Clear all cached templates
    /// </summary>
    void Clear();
}
