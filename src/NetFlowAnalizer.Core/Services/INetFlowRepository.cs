using NetFlowAnalizer.Core.Models;

namespace NetFlowAnalizer.Core;

public interface INetFlowRepository
{
    Task SaveRecordAsync(IEnumerable<INetFlowRecord> records,
        CancellationToken cancellationToken=default);

    Task<IEnumerable<INetFlowRecord>> GetRecordsByTimeRangeAsync(
        DateTime startTime,
        DateTime endTime,
        CancellationToken cancellationToken = default);

    Task<long> GetTotalRecordsCountAsync(CancellationToken cancellationToken = default);
}
