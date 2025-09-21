using System.Data.SqlClient;

namespace App.Auth.Core.Interfaces
{
    public interface IConnectionFactory
    {
        SqlConnection CreateConnection();
    }
}
