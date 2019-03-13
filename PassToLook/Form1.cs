using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Timers;
using System.Windows.Forms;
using LogExport.Comm;

namespace PassToLook
{
    public partial class Form1 : Form
    {
        public Form1()
        {
            InitializeComponent();
            comcon.SelectedIndex = 0;
            CheckForIllegalCrossThreadCalls = false;

            Thread.Sleep(500);

            button3_Click("t", new EventArgs());

        }

        private void button1_Click(object sender, EventArgs e)
        {
            if (txtKey.Text == "")
            {
                MessageBox.Show("key不能为空！");
                return;
            }
            if (txtmi.Text == "")
            {
                MessageBox.Show("密文不能为空！");
                return;
            }
            AES.AesKey = txtKey.Text;
            txtming.Text = AES.UrlDecrypt(txtmi.Text);

        }

        private void button2_Click(object sender, EventArgs e)
        {
            if (txtKey.Text == "")
            {
                MessageBox.Show("key不能为空！");
                return;
            }
            if (txtming.Text == "")
            {
                MessageBox.Show("明文不能为空！");
                return;
            }
            AES.AesKey = txtKey.Text;
            txtmi.Text = AES.UrlEncrypt(txtming.Text);
        }

        private void button3_Click(object sender, EventArgs e)
        {
            string constr = comcon.Text;
            PMySqlHelper mysql = new PMySqlHelper(constr);
            string sql = @"SELECT a.id,a.username,a.userpsw, b.categoryname,a.errorcount,a.errordate,a.userrole FROM `tb_user`  a
LEFT JOIN tb_category b 
on a.userrole=b.id";
            DataTable dt = mysql.ExecuteDataTable(sql);
            AES.AesKey = txtKey.Text;

            foreach (DataRow row in dt.Rows)
            {
                string temp = AES.UrlDecrypt(row["userpsw"].ToString());
                row["userpsw"] = temp;
            }


            dataGridView1.DataSource = dt;


        }

        private void dataGridView1_CellClick(object sender, DataGridViewCellEventArgs e)
        {

            /* string name0 = this.dataGridView1.Columns[e.ColumnIndex].Name;
             string name1=this.dataGridView1.Columns[this.dataGridView1.CurrentCell.ColumnIndex].Name;*/

            txtming.Text = dataGridView1.Rows[e.RowIndex].Cells[e.ColumnIndex].Value.ToString();
        }

        private void button4_Click(object sender, EventArgs e)
        {
            if (this.txtRsaming.Text == "")
            {
                MessageBox.Show("明文不能为空！");
                return;
            }
            string encodeString = RSACryption.Encrypt(this.txtRsaming.Text);
            this.txtRsami.Text = encodeString;
        }

        private void button5_Click(object sender, EventArgs e)
        {
            if (this.txtRsami.Text == "")
            {
                MessageBox.Show("密文不能为空！");
                return;
            }
            string decode = RSACryption.Decrypt(this.txtRsami.Text);
            this.txtRsaming.Text = decode;
        }


    }
}
