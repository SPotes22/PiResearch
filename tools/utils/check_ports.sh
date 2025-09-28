echo "checking with legacy..."
sudo netstat -tuln
echo "checking with dependecies.."
sudo ss -tuln
echo "force checking :80 "
sudo netstat -tuln | grep :80 o sudo ss -tuln | grep :80
