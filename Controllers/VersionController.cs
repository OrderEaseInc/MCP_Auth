using Microsoft.AspNetCore.Mvc;

namespace OrderEase.DabProxy.Controllers;

[ApiController]
public class VersionController : ControllerBase
{
    [HttpGet("/version")]
    public IActionResult Get()
    {
        var assembly = typeof(VersionController).Assembly;
        var version = assembly.GetName().Version?.ToString() ?? "unknown";
        var buildTime = new FileInfo(assembly.Location).LastWriteTimeUtc;

        return Ok(new
        {
            version,
            builtAt = buildTime.ToString("O")
        });
    }
}
